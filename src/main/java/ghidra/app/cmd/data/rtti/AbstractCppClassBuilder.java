package ghidra.app.cmd.data.rtti;

import java.util.*;
import java.util.function.IntSupplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CompositeDataTypeElementInfo;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;

public abstract class AbstractCppClassBuilder {

	protected static final String SUPER = "super_";

	private final Program program;
	protected Structure struct;
	private final CategoryPath path;
	private final ClassTypeInfo type;

	private Map<CompositeDataTypeElementInfo, String> dtComps = Collections.emptyMap();

	protected AbstractCppClassBuilder(ClassTypeInfo type) {
		this.type = type;
		GhidraClass gc = type.getGhidraClass();
		this.program = gc.getSymbol().getProgram();
		this.struct = ClassTypeInfoUtils.getPlaceholderStruct(type, program.getDataTypeManager());
		this.struct = resolveStruct(struct);
		this.path = new CategoryPath(TypeInfoUtils.getCategoryPath(type), type.getName());
	}

	protected abstract AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent);

	protected ClassTypeInfo getType() {
		return type;
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

	public Structure getDataType() {
		if (struct.isDeleted()) {
			struct = ClassTypeInfoUtils.getPlaceholderStruct(
				type, program.getDataTypeManager());
		}
		Integer id = null;
		boolean success = false;
		if (program.getCurrentTransactionInfo() == null) {
			id = program.startTransaction("creating datatype for "+type.getName());
		}

		try {
			stashComponents();
			Map<ClassTypeInfo, Integer> baseMap = getBaseOffsets();
			boolean primaryBaseSet = false;
			for (ClassTypeInfo parent : baseMap.keySet()) {
				AbstractCppClassBuilder parentBuilder = getParentBuilder(parent);
				Structure parentStruct = parentBuilder.getSuperClassDataType();
				String memberName = SUPER + parent.getName();
				int offset = baseMap.get(parent);
				if (offset == 0) {
					if (parentStruct.isNotYetDefined()) {
						// it is an empty class, interface or essentially a namespace
						continue;
					}
					if (!primaryBaseSet) {
						replaceComponent(struct, parentStruct, memberName, 0);
						primaryBaseSet = true;
					}
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
			getSuperClassDataType();
			success = true;
		} finally {
			if (id != null) {
				program.endTransaction(id, success);
			}
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
			superStruct = resolveStruct(superStruct);
			int ordinal = getFirstVirtualOrdinal(superStruct);
			if (ordinal != -1) {
				ComponentInfo[] comps = new ComponentInfo[ordinal];
				DataTypeComponent[] dcomps = superStruct.getDefinedComponents();
				for (int i = 0; i < ordinal; i++) {
					comps[i] = new ComponentInfo(dcomps[i]);
				}
				superStruct.deleteAll();
				for (ComponentInfo comp : comps) {
					comp.insert(superStruct);
				}
			}
			addVptr(superStruct);
			//if (!superStruct.isMachineAligned()) {
			//	trimStructure(superStruct);
			//}
			return superStruct;
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

	protected static Structure resolveStruct(Structure struct) {
		DataTypeManager dtm = struct.getDataTypeManager();
		return (Structure) dtm.resolve(struct, DataTypeConflictHandler.KEEP_HANDLER);
	}

	protected int getFirstVirtualOrdinal(Structure superStruct) {
		Set<String> parents = type.getVirtualParents()
			.stream()
			.map(this::getParentBuilder)
			.map(AbstractCppClassBuilder::getSuperName)
			.collect(Collectors.toSet());
		DataTypeComponent[] comps = superStruct.getDefinedComponents();
		return getReverseIndexStream(comps.length)
			.filter(i -> parents.contains(comps[i].getFieldName()))
			.findFirst()
			.orElse(-1);
	}

	private static IntStream getReverseIndexStream(int max) {
		return IntStream.generate(new ReverseIndexSupplier(max - 1))
			.limit(max);
	}

	private boolean validFieldName(String name) {
		if (name == null) {
			return true;
		}
		return !name.startsWith(SUPER) && !name.contains("_vptr");
	}

	private void stashComponents() {
		if (struct.isPackingEnabled()) {
			struct.setPackingEnabled(false);
		}
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
			DataTypeComponent replaced = struct.getComponentContaining(offset);
			if (replaced != null && !validFieldName(replaced.getFieldName())) {
				continue;
			}
			replaceComponent(struct, (DataType) comp.getDataTypeHandle(),
							 dtComps.get(comp), offset);
		}
	}

	private static final class ReverseIndexSupplier implements IntSupplier {

		private int index;

		ReverseIndexSupplier(int index) {
			this.index = index;
		}

		@Override
		public int getAsInt() {
			return index--;
		}
	}
	
	private static class ComponentInfo {
		final DataType type;
		final String name;
		final String comment;
		final int offset;
		
		ComponentInfo(DataTypeComponent comp) {
			type = comp.getDataType();
			name = comp.getFieldName();
			comment = comp.getComment();
			offset = comp.getOffset();
		}
		
		void insert(Structure struct) {
			struct.insertAtOffset(offset, type, type.getLength(), name, comment);
		}
	}
}
