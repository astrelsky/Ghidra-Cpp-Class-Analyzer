package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.AbstractSiClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.InvalidDataTypeException;

import static ghidra.program.model.data.Undefined.isUndefined;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GccCppClassBuilder extends AbstractCppClassBuilder {

    private static final String VPTR = "_vptr";

    public GccCppClassBuilder(ClassTypeInfo type) {
        super(type);
    }

    @Override
    protected AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent) {
        return new GccCppClassBuilder(parent);
    }

    @Override
    protected void addVptr() {
        try {
            getType().getVtable().validate();
        } catch (InvalidDataTypeException e) {
            return;
        }
        DataType vptr = ClassTypeInfoUtils.getVptrDataType(getProgram(), getType());
        DataTypeComponent comp = struct.getComponentAt(0);
        if (comp == null || isUndefined(comp.getDataType())) {
            if (vptr != null) {
                clearComponent(struct, getProgram().getDefaultPointerSize(), 0);
                struct.insertAtOffset(0, vptr, getProgram().getDefaultPointerSize(), VPTR, null);
            }
        } else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
            clearComponent(struct, getProgram().getDefaultPointerSize(), 0);
            struct.insertAtOffset(0, vptr, getProgram().getDefaultPointerSize(), VPTR, null);
        }
    }

    @Override
    protected Map<ClassTypeInfo, Integer> getBaseOffsets() throws InvalidDataTypeException {
        if (!getType().hasParent()) {
            return Collections.emptyMap();
        }
        if (getType() instanceof AbstractSiClassTypeInfoModel) {
            try {
                VtableModel vtable = (VtableModel) getType().getVtable();
                long offset = vtable.getOffset(0, 1);
                if (offset < Long.MAX_VALUE && offset > 0) {
                    return Map.of(getType().getParentModels()[0], (int) offset);
                }
            } catch (InvalidDataTypeException e) {}
            return Map.of(getType().getParentModels()[0], 0);
        }
        if (getType() instanceof VmiClassTypeInfoModel) {
            VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) getType();
            List<Long> offsets = vmi.getOffsets();
            ClassTypeInfo[] parents = vmi.getParentModels();
            Map<ClassTypeInfo, Integer> result = new HashMap<>(parents.length);
            for (int i = 0; i < parents.length; i++) {
                result.put(parents[i], offsets.get(i).intValue());
            }
            return result;
        }
        return null;
    }
}
