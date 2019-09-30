package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
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
        int id = dtm.startTransaction("Creating Class DataType for "+getName());
        AbstractClassTypeInfoModel parent = (AbstractClassTypeInfoModel) getParentModels()[0];
        Structure parentStruct = parent.getSuperClassDataType();
        if (!parentStruct.getDataTypeManager().equals(program.getDataTypeManager())) {
            parentStruct = (Structure) parentStruct.clone(program.getDataTypeManager());
        }
        replaceComponent(
            struct, parentStruct, SUPER+parent.getName(), 0);
        addVptr(struct);
        dtm.endTransaction(id, true);
        return resolveStruct(struct);
    }

    private static Address getBaseTypeAddress(Program program, Address address) {
        Address pointerAddress = address.add(program.getDefaultPointerSize() << 1);
        return getAbsoluteAddress(program, pointerAddress);
    }

    @Override
    public boolean hasParent() {
        return true;
    }

    @Override
    public ClassTypeInfo[] getParentModels() throws InvalidDataTypeException {
        validate();
        Address baseAddress = getBaseTypeAddress(program, address);
        if (baseAddress != null && program.getMemory().getBlock(baseAddress).isInitialized()) {
            TypeInfo parent = TypeInfoFactory.getTypeInfo(program, baseAddress);
            if (parent instanceof ClassTypeInfo) {
                return new ClassTypeInfo[]{
                    (ClassTypeInfo) parent
                    };
            }
        }
        RelocationTable table = program.getRelocationTable();
        Relocation reloc = table.getRelocation(
            address.add(program.getDefaultPointerSize() << 1));
        if (reloc != null && reloc.getSymbolName() != null) {
            TypeInfo parent = TypeInfoUtils.getExternalTypeInfo(program, reloc);
            if (parent instanceof ClassTypeInfo) {
                return new ClassTypeInfo[]{
                    (ClassTypeInfo) parent
                    };
            }
        }
        return new ClassTypeInfo[0];
    }

    @Override
    public Set<ClassTypeInfo> getVirtualParents() throws InvalidDataTypeException {
        validate();
        ClassTypeInfo[] parents = getParentModels();
        return parents[0].getVirtualParents();
    }

}
