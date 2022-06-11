package cppclassanalyzer.vs;

import static ghidra.program.model.data.Undefined.isUndefined;

import java.util.Map;

import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

public class VsCppClassBuilder extends AbstractCppClassBuilder {

	private static final String VFPTR = "_vfptr";
	private static final String VBPTR = "_vbptr";

	public VsCppClassBuilder(VsClassTypeInfo type) {
		super(type);
	}

	@Override
	protected AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent) {
		return new VsCppClassBuilder((VsClassTypeInfo) parent);
	}

	@Override
	protected void addVptr(Structure struct) {
		try {
			addPointers(struct);
		} catch (InvalidDataTypeException e) {
			return;
		}
	}

	private void addVfptr(Structure struct, int offset) {
		ClassTypeInfo type = getType();
		Program program = getProgram();
		DataType vfptr = ClassTypeInfoUtils.getVptrDataType(program, type);
		DataTypeComponent comp = struct.getComponentContaining(offset);
		if (comp == null || isUndefined(comp.getDataType())) {
			replaceComponent(struct, vfptr, VFPTR, offset);
		} else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
			replaceComponent(struct, vfptr, VFPTR, offset);
		}
	}


	/**  {@link Rtti4Model#getVbTableOffset} */
	private void addVbptr(Structure struct, int offset) throws InvalidDataTypeException {
		Program program = getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		int ptrSize = program.getDefaultPointerSize();
		DataType vbptr = dtm.getPointer(
			MSDataTypeUtils.getPointerDisplacementDataType(program), ptrSize);
		DataTypeComponent comp = struct.getComponentContaining(offset);
		if (comp == null || isUndefined(comp.getDataType())) {
			replaceComponent(struct, vbptr, VBPTR, offset);
		} else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
			replaceComponent(struct, vbptr, VBPTR, offset);
		}
	}

	private void addPointers(Structure struct) throws InvalidDataTypeException {
		VsClassTypeInfo type = getType();
		int offset = 0;
		Vtable vtable = type.getVtable();
		if (Vtable.isValid(vtable)) {
			addVfptr(struct, offset);
			offset = getProgram().getDefaultPointerSize();
		}
		if (!type.getVirtualParents().isEmpty()) {
			addVbptr(struct, offset);
		}
	}

	@Override
	protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
		return getType().getBaseOffsets();
	}

	@Override
	protected VsClassTypeInfo getType() {
		return (VsClassTypeInfo) super.getType();
	}
}
