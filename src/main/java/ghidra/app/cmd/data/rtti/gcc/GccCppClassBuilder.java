package ghidra.app.cmd.data.rtti.gcc;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

import static ghidra.program.model.data.Undefined.isUndefined;

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
        if (getType().getVtable() == Vtable.NO_VTABLE) {
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
    protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
        if (!getType().hasParent()) {
            return Collections.emptyMap();
        }
        if (getType().getParentModels().length == 1) {
			if (Vtable.isValid(getType().getVtable())) {
				final VtableModel vtable = (VtableModel) getType().getVtable();
				final long offset = vtable.getOffset(0, 1);
				if (offset < Long.MAX_VALUE && offset > 0) {
					return Map.of(getType().getParentModels()[0], (int) offset);
				}
			}
            return Map.of(getType().getParentModels()[0], 0);
        }
        if (getType() instanceof VmiClassTypeInfoModel) {
            final VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) getType();
            final List<Long> offsets = vmi.getOffsets();
            final ClassTypeInfo[] parents = vmi.getParentModels();
            final Map<ClassTypeInfo, Integer> result = new HashMap<>(parents.length);
            for (int i = 0; i < parents.length; i++) {
                result.put(parents[i], offsets.get(i).intValue());
            }
            return result;
        }
        return null;
    }
}
