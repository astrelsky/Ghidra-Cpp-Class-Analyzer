package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;


/**
 * Model for the __function_type_info class.
 */
public final class FunctionTypeInfoModel extends AbstractTypeInfoModel {

    public static final String STRUCTURE_NAME = "__function_type_info";
    public static final String ID_STRING = "N10__cxxabiv120__function_type_infoE";
    private static final String DESCRIPTION = "Model for Function Type Info";

    private DataType typeInfoDataType;

    public FunctionTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    @Override
    public DataType getDataType() {
        if (typeInfoDataType == null) {
            typeInfoDataType = getDataType(STRUCTURE_NAME, DESCRIPTION);
        }
        return typeInfoDataType;
    }

    /**
     * @see ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel#getDataType(DataTypeManager)
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
    }

}
