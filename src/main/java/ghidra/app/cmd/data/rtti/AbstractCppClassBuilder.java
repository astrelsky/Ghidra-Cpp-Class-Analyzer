package ghidra.app.cmd.data.rtti;

import java.util.*;

import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.Vptr;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CompositeDataTypeElementInfo;
import ghidra.util.exception.AssertException;

public abstract class AbstractCppClassBuilder {

	protected static final String SUPER = "super_";

	private final Program program;
	protected Structure struct;
	private final CategoryPath path;
	private final ClassTypeInfo type;
	private Vptr[] vptrs = null;

	private Map<CompositeDataTypeElementInfo, String> dtComps = Collections.emptyMap();

	protected AbstractCppClassBuilder(ClassTypeInfo type) {
		this.type = type;
		GhidraClass gc = type.getGhidraClass();
		this.program = gc.getSymbol().getProgram();
		this.struct = ClassTypeInfoUtils.getPlaceholderStruct(type, program.getDataTypeManager());
		this.struct = resolveStruct(struct);
		this.path = new CategoryPath(TypeInfoUtils.getCategoryPath(type), type.getName());

		Vtable vtable = getType().getVtable();
		if (Vtable.isValid(vtable)) {
			this.vptrs = ClassTypeInfoUtils.getVptrDataTypes(getProgram(), getType());
		}
	}

	protected ClassTypeInfo getType() {
		return type;
	}

	protected Vptr[] getVptrs() {
		return vptrs;
	}

	protected final Program getProgram() {
		return program;
	}

	protected int pointerSize() {
		return program.getDefaultPointerSize();
	}

	protected abstract Map<ClassTypeInfo, Integer> getBaseOffsets();

	/**
	 * Add implementation-specific virtual pointers for the subobject residing at the
	 * given offset into the beginning of the given struct.
	 * @param struct the struct to add the vptrs to.
	 * @return offset the offset of the subobject inside the type.
	 */
	protected abstract void addVptrs(Structure struct, int offset);
	protected abstract boolean invalidFieldName(String name);

	public Structure getDataType() {
		if (struct.isDeleted()) {
			struct = ClassTypeInfoUtils.getPlaceholderStruct(type, program.getDataTypeManager());
			struct = resolveStruct(struct);
		}

		boolean success = false;
		try {
			stashComponents();

			Map<ClassTypeInfo, Integer> baseMap = getBaseOffsets();
			for (ClassTypeInfo parent : baseMap.keySet()) {
				int offset = baseMap.get(parent);
				if (offset == 0) {
					// A direct or indirect primary base - add later.
				} else if (offset < 0) {
					// it is contained within another base class
					// or unable to resolve and already reported
					continue;
				} else {
					Structure parentStruct = getSuperStruct(parent);
					addVptrs(parentStruct, offset);
					replaceComponent(struct, parentStruct, SUPER+parent.getName(), offset);
				}
			}

			// The derived class shares its own vtable with the primary base's at offset 0.
			// Embed this vtable directly into the derived struct.
			addVptrs(struct, 0);

			fixComponents();
			success = true;
		} finally {
			Integer id = null;
			if (program.getCurrentTransaction() == null) {
				id = program.startTransaction("creating datatype for "+type.getName());
			}
			if (id != null) {
				program.endTransaction(id, success);
			}
		}
		return struct;
	}

	protected Structure getSuperStruct(ClassTypeInfo superType) {
		DataTypeManager dtm = program.getDataTypeManager();
		StructureDataType struct = new StructureDataType(path, SUPER+superType.getName(), 0, dtm);
		return (Structure) dtm.resolve(struct, DataTypeConflictHandler.KEEP_HANDLER);
	}

	protected static void replaceComponent(Structure struct, DataType parent,
			String name, int offset) {
		clearComponent(struct, parent.getLength(), offset);
		struct.insertAtOffset(offset, parent, parent.getLength(), name, null);
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

	protected static Structure resolveStruct(Structure struct) {
		DataTypeManager dtm = struct.getDataTypeManager();
		return (Structure) dtm.resolve(struct, DataTypeConflictHandler.KEEP_HANDLER);
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
				if (invalidFieldName(fieldName)) {
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
			if (replaced != null && !invalidFieldName(replaced.getFieldName())) {
				continue;
			}
			replaceComponent(struct, (DataType) comp.getDataTypeHandle(),
							 dtComps.get(comp), offset);
		}
	}
}
