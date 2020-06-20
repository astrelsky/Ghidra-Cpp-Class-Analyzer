package ghidra.app.cmd.data.rtti;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.program.model.data.AlignedStructureInspector;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.AlignedStructurePacker.StructurePackResult;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CompositeDataTypeElementInfo;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;

public abstract class AbstractCppClassBuilder {

	protected static final String SUPER = "super_";

	private Program program;
	protected Structure struct;
	private CategoryPath path;
	private ClassTypeInfo type;

	// this is lazyness
	private boolean built = false;

	private Map<CompositeDataTypeElementInfo, String> dtComps = Collections.emptyMap();

	protected AbstractCppClassBuilder(ClassTypeInfo type) {
		this.type = type;
		GhidraClass gc = type.getGhidraClass();
		this.program = gc.getSymbol().getProgram();
		this.struct = ClassTypeInfoUtils.getPlaceholderStruct(
			type, program.getDataTypeManager());
		this.path = new CategoryPath(struct.getCategoryPath(), type.getName());
	}

	protected abstract AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent);

	protected ClassTypeInfo getType() {
		return type;
	}

	protected CategoryPath getPath() {
		return path;
	}

	protected final Program getProgram() {
		return program;
	}

	private String getSuperName() {
		return SUPER + type.getName();
	}

	protected final void addVptr() {
		addVptr(struct);
	}

	protected abstract Map<ClassTypeInfo, Integer> getBaseOffsets();
	protected abstract void addVptr(Structure struct);

	private static boolean containsMember(Structure struct, String name) {
		return Arrays.stream(struct.getComponents())
			.map(DataTypeComponent::getFieldName)
			.filter(Objects::nonNull)
			.anyMatch(name::equals);
	}

	public Structure getDataType() {
		if (built) {
			return struct;
		}
		if (struct.isDeleted()) {
			struct = ClassTypeInfoUtils.getPlaceholderStruct(
				type, program.getDataTypeManager());
		}
		Integer id = null;
		if (program.getCurrentTransaction() == null) {
			id = program.startTransaction("creating datatype for "+type.getName());
		}
		stashComponents();
		int pointerSize = program.getDefaultPointerSize();
		Map<ClassTypeInfo, Integer> baseMap = getBaseOffsets();
		int primaryBaseCount = 0;
		for (ClassTypeInfo parent : baseMap.keySet()) {
			AbstractCppClassBuilder parentBuilder = getParentBuilder(parent);
			Structure parentStruct = parentBuilder.getSuperClassDataType();
			String memberName = SUPER + parent.getName();
			int offset = baseMap.get(parent);
			if (offset == 0 && parentStruct.getLength() > pointerSize) {
				// it is an empty class, interface or essentially a namespace.
				if (primaryBaseCount++ > 0) {
					Structure comp = (Structure) struct.getComponent(0).getDataType();
					if (containsMember(comp, memberName)) {
						continue;
					}
					if (containsMember(parentStruct, struct.getComponent(0).getFieldName())) {
						replaceComponent(struct, parentStruct, memberName, 0);
						continue;
					}
				}
				replaceComponent(struct, parentStruct, memberName, 0);
			} else if (offset < 0) {
				// it is contained within another base class
				// or unable to resolve and already reported
				continue;
			} else {
				replaceComponent(struct, parentStruct, memberName, offset);
			}
		}
		addVptr();
		fixComponents();
		built = true;
		struct = resolveStruct(struct);
		resolveStruct(getSuperClassDataType());
		if (id != null) {
			program.endTransaction(id, true);
		}
		return struct;
	}

	protected void setSuperStructureCategoryPath(Structure parent) {
		try {
			parent.setCategoryPath(path);
			parent.setName(SUPER+parent.getName());
		} catch (InvalidNameException | DuplicateNameException e) {
			Msg.error(
				this, "Failed to change placeholder struct "+type.getName()+"'s CategoryPath", e);
		}
	}

	protected Structure getSuperClassDataType() {
		if (type.getVirtualParents().isEmpty()) {
			return struct;
		}
		DataTypeManager dtm = program.getDataTypeManager();
		DataTypePath dtPath = new DataTypePath(path, SUPER+type.getName());
		DataType dt = dtm.getDataType(dtPath);
		if (dt == null) {
			Structure superStruct = (Structure) struct.copy(dtm);
			setSuperStructureCategoryPath(superStruct);
			deleteVirtualComponents(superStruct);
			addVptr(superStruct);
			if (!superStruct.isMachineAligned()) {
				trimStructure(superStruct);
			}
			return resolveStruct(superStruct);
		}
		return (Structure) dt;
	}

	protected static void clearComponent(Structure struct, int length, int offset) {
		if (offset >= struct.getLength()) {
			return;
		}
		for (int size = 0; size < length;) {
			DataTypeComponent comp = struct.getComponentAt(offset);
			if (comp!= null) {
				size += comp.getLength();
			} else {
				size++;
			}
			struct.deleteAtOffset(offset);
		}
	}

	protected static void replaceComponent(Structure struct, DataType parent,
		String name, int offset) {
			clearComponent(struct, parent.getLength(), offset);
			struct.insertAtOffset(offset, parent, parent.getLength(), name, null);
	}

	protected static void trimStructure(Structure struct) {
		DataTypeComponent[] comps = struct.getDefinedComponents();
		if (comps.length == 0) {
			return;
		}
		int endOffset =  comps[comps.length-1].getEndOffset()+1;
		while (struct.getLength() > endOffset) {
			struct.deleteAtOffset(endOffset);
		}
	}

	protected static Structure resolveStruct(Structure struct) {
		DataTypeManager dtm = struct.getDataTypeManager();
		struct =
			(Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		if (struct.getNumComponents() == 0 || struct.isMachineAligned()) {
			return struct;
		}
		StructurePackResult results = AlignedStructureInspector.packComponents(struct);
		if (!results.componentsChanged) {
			struct.setMinimumAlignment(results.alignment);
		}
		return struct;
	}

	protected void deleteVirtualComponents(Structure superStruct) {
		Set<String> parents = type.getVirtualParents()
			.stream()
			.map(this::getParentBuilder)
			.map(AbstractCppClassBuilder::getSuperName)
			.collect(Collectors.toSet());
		DataTypeComponent[] comps = superStruct.getDefinedComponents();
		for (DataTypeComponent comp : comps) {
			if (parents.contains(comp.getFieldName())) {
				int ordinal = comp.getOrdinal();
				int numComponents = superStruct.getNumComponents() - 1;
				int[] ordinals = IntStream.rangeClosed(ordinal, numComponents).toArray();
				superStruct.delete(ordinals);
				break;
			}
		}
	}

	private boolean validFieldName(String name) {
		if (name == null) {
			return true;
		}
		return !name.startsWith(SUPER) && !name.contains("_vptr");
	}

	private void stashComponents() {
		if(dtComps.isEmpty()) {
			dtComps = new HashMap<>(struct.getNumDefinedComponents());
			for (DataTypeComponent comp : struct.getDefinedComponents()) {
				if (comp.getDataType() == null) {
					String msg = struct.getDataTypePath().toString()
						+ " is corrupted and must be deleted through the user interface";
					throw new AssertException(msg);
				}
				String fieldName = comp.getFieldName();
				if (validFieldName(fieldName)) {
					if (!comp.getDataType().isNotYetDefined()) {
						CompositeDataTypeElementInfo savedComp = new CompositeDataTypeElementInfo(
							comp.getDataType(), comp.getOffset(),
							comp.getLength(), comp.getDataType().getAlignment());
						dtComps.put(savedComp, comp.getFieldName());
					}
				}
			}
			struct.deleteAll();
		}
	}

	private void fixComponents() {
		for (CompositeDataTypeElementInfo comp : dtComps.keySet()) {
			int offset = comp.getDataTypeOffset();
			DataTypeComponent replaced = struct.getComponentAt(offset);
			if (replaced != null && !validFieldName(replaced.getFieldName())) {
				continue;
			}
			replaceComponent(struct, (DataType) comp.getDataTypeHandle(),
							 dtComps.get(comp), offset);
		}
	}
}
