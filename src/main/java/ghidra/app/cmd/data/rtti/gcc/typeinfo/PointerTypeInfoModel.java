package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.getCxxAbiCategoryPath;

/**
 * Model for the __pointer_type_info class.
 */
public final class PointerTypeInfoModel extends AbstractPBaseTypeInfoModel {

    public static final String STRUCTURE_NAME = "__pointer_type_info";
    public static final String ID_STRING = "N10__cxxabiv119__pointer_type_infoE";
    private static final String DESCRIPTION = "Model for Pointer Type Info";
    private DataType typeInfoDataType;

    public PointerTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    /**
     * Gets the __pointer_type_info datatype.
     */
    @Override
    public DataType getDataType() {
        if (typeInfoDataType == null) {
            typeInfoDataType = getDataType(program.getDataTypeManager());
        }
        return typeInfoDataType;
    }

    /**
     * Gets the __pointer_type_info datatype.
     * @param dtm
     * @return
     */
    public static DataType getDataType(DataTypeManager dtm) {
        DataType superDt = getPBase(dtm);
        DataType existingDt = dtm.getDataType(superDt.getCategoryPath(), STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        StructureDataType struct = new StructureDataType(
            getCxxAbiCategoryPath(), STRUCTURE_NAME, 0, dtm);
        struct.add(superDt, SUPER_NAME, null);
        struct.setDescription(DESCRIPTION);
        return alignDataType(struct, dtm);
    }

}
