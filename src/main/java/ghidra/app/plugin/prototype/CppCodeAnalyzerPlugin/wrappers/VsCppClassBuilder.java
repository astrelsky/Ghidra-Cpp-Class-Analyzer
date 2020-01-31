package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers;

import static ghidra.program.model.data.Undefined.isUndefined;

import java.util.Map;

import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;

public class VsCppClassBuilder extends AbstractCppClassBuilder {

    private static final String VFPTR = "_vfptr";
    private static final String VBPTR = "_vbptr";

    public VsCppClassBuilder(RttiModelWrapper type) {
        super(type);
    }

    @Override
    protected AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent) {
        return new VsCppClassBuilder((RttiModelWrapper) parent);
    }

    @Override
    protected void addVptr() {
        try {    
            addPointers();
        } catch (InvalidDataTypeException e) {
            return;
        }
    }

    private void addVfptr(int offset) {
		final ClassTypeInfo type = getType();
		final Program program = getProgram();
		final DataType vfptr = ClassTypeInfoUtils.getVptrDataType(program, type);
        DataTypeComponent comp = struct.getComponentAt(offset);
        if (comp == null || isUndefined(comp.getDataType())) {
			replaceComponent(struct, vfptr, VFPTR, offset);
        } else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
            replaceComponent(struct, vfptr, VFPTR, offset);
        }
	}

    private void addVbptr(int offset) throws InvalidDataTypeException {
		final Program program = getProgram();
		final DataTypeManager dtm = program.getDataTypeManager();
        final int ptrSize = program.getDefaultPointerSize();
        final DataType vbptr = dtm.getPointer(
			MSDataTypeUtils.getPointerDisplacementDataType(program), ptrSize);
        DataTypeComponent comp = struct.getComponentAt(offset);
        if (comp == null || isUndefined(comp.getDataType())) {
			replaceComponent(struct, vbptr, VBPTR, offset);
        } else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
			replaceComponent(struct, vbptr, VBPTR, offset);
        }
	}

	private static boolean hasVtable(RttiModelWrapper type) {
		return Vtable.isValid(type.getVtable());
	}
	
	private void addPointers() throws InvalidDataTypeException {
		final int vfPtrOffset;
		final int vbPtrOffset;
		final int ptrSize = getProgram().getDefaultPointerSize();
		final RttiModelWrapper type = getType();
		final boolean hasVtable = hasVtable(type);
		if (!type.getVirtualParents().isEmpty()) {
			final Rtti1Model base = type.getBaseModel();
			if (!(base.getPDisp() > 0 && base.getVDisp() > 0) || base.getPDisp() < 0) {
				vbPtrOffset = 0;
				vfPtrOffset = hasVtable ? ptrSize : -1;
			} else {
				vfPtrOffset = hasVtable ? 0 : -1;
				vbPtrOffset = ptrSize;
			}
		} else {
			vbPtrOffset = -1;
			vfPtrOffset = hasVtable ? 0 : -1;
		}
		if (vbPtrOffset >= 0) {
			addVbptr(vbPtrOffset);
		}
		if (vfPtrOffset >= 0) {
			addVfptr(vfPtrOffset);
		}
	}

    @Override
    protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
        return getType().getBaseOffsets();
	}
	
	@Override
	protected RttiModelWrapper getType() {
		return (RttiModelWrapper) super.getType();
	}
}
