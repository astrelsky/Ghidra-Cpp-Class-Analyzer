package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.stream.IntStream;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

/**
 * Base Model for __si_class_type_info and its derivatives.
 */
public abstract class AbstractSiClassTypeInfoModel extends AbstractClassTypeInfoModel {

    protected AbstractSiClassTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    protected Structure getSuperClassDataType() throws InvalidDataTypeException {
        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = super.getSuperClassDataType();
        if (!ClassTypeInfoUtils.isPlaceholder(struct)) {
            return struct;
        }
        struct = getClassDataType();
        VtableModel vtable = (VtableModel) getVtable();
        if (vtable == null) {
            return struct;
        }
        long[] offsets = vtable.getOffsetArray();
        if (offsets.length ==1) {
            // finished
            return struct;
        }
        Structure superStruct = (Structure) struct.copy(dtm);
        setSuperStructureCategoryPath(superStruct);
        superStruct.deleteAtOffset((int) offsets[1]);
        DataTypeComponent[] comps = superStruct.getComponents();
        if (comps.length > 0) {
            int ordinal = comps[comps.length-1].getOrdinal();
            int[] ordinals = IntStream.rangeClosed(ordinal+1, superStruct.getNumComponents() - 1).toArray();
            superStruct.delete(ordinals);
        }
        return resolveStruct(struct);
    }

    @Override
    public Structure getClassDataType(boolean repopulate) throws InvalidDataTypeException {
        validate();
        if (getName().contains(TypeInfoModel.STRUCTURE_NAME)) {
            return (Structure) getDataType();
        }
        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = ClassTypeInfoUtils.getPlaceholderStruct(this, dtm);
        if (!ClassTypeInfoUtils.isPlaceholder(struct) && !repopulate) {
            return struct;
        }
        struct.setDescription("");
        VtableModel vtable = (VtableModel) getVtable();
        if (vtable == null) {
            return struct;
        }
        long[] offsets = vtable.getOffsetArray();
        AbstractClassTypeInfoModel parent = (AbstractClassTypeInfoModel) getParentModels()[0];
        if (offsets.length == 1) {
            // no virtual base
            replaceComponent(struct, parent.getSuperClassDataType(), SUPER+parent.getName(), 0);
            return struct;
        }
        replaceComponent(
            struct, parent.getSuperClassDataType(), SUPER+parent.getName(), (int) offsets[1]);
        addVptr(struct);
        return resolveStruct(struct);
    }

    private static Address getBaseTypeAddress(Program program, Address address) {
        return getAbsoluteAddress(program, address.add(program.getDefaultPointerSize() << 1));
    }

    @Override
    public boolean hasParent() {
        return true;
    }

    @Override
    public ClassTypeInfo[] getParentModels() throws InvalidDataTypeException {
        validate();
        return new ClassTypeInfo[]{
            (ClassTypeInfo) TypeInfoFactory.getTypeInfo(
                program, getBaseTypeAddress(program, address))
            };
    }

}
