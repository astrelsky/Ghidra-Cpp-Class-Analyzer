package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.DataType;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;

/**
 * Model for the __class_type_info class.
 */
public class ClassTypeInfoModel extends AbstractClassTypeInfoModel {

    public static final String STRUCTURE_NAME = "__class_type_info";
    private static final String DESCRIPTION = "Model for Class Type Info";

    public static final String ID_STRING = "N10__cxxabiv117__class_type_infoE";

    public ClassTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public DataType getDataType() {
        return getDataType(STRUCTURE_NAME, DESCRIPTION);
    }

    /**
     * @see ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel#getDataType(DataTypeManager)
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
    }

    /**
     * Gets a pointer to a __class_type_info datatype.
     * @param DataTypeManager
     * @return __class_type_info *
     */
    public static Pointer getPointer(DataTypeManager dtm) {
        return PointerDataType.getPointer(getDataType(dtm), dtm);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    @Override
    public boolean hasParent() {
        return false;
    }

    @Override
    public ClassTypeInfo[] getParentModels() {
        return new ClassTypeInfo[0];
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
        addVptr(struct);
        dtm.endTransaction(id, true);
        return struct;
    }

    @Override
    protected Structure getSuperClassDataType() throws InvalidDataTypeException {
        return getClassDataType();
    }
}
