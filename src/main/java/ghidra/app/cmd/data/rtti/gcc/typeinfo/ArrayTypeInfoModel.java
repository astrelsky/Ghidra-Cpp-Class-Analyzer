package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

/**
 * Model for the __array_type_info class.
 */
public final class ArrayTypeInfoModel extends AbstractTypeInfoModel {

    private static final String DESCRIPTION = "Model for Array Type Info";
    public static final String STRUCTURE_NAME = "__array_type_info";

    public static final String ID_STRING = "N10__cxxabiv117__array_type_infoE";
    private static final Pattern ARRAY_PATTERN = Pattern.compile(".*A(\\d*)_(.*)");
    
    private DataType dataType;
	private DataType typeInfoDataType;
	
	public static ArrayTypeInfoModel getModel(Program program, Address address) {
		if (isValid(program, address, ID_STRING)) {
			return new ArrayTypeInfoModel(program, address);
		}
		return null;
	}

    private ArrayTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    /**
     * Gets the __array_type_info datatype.
     */
    @Override
    public DataType getDataType() {
        if (typeInfoDataType == null) {
            typeInfoDataType = getDataType(STRUCTURE_NAME, DESCRIPTION);
        }
        return typeInfoDataType;
    }


    /**
     * Gets the __array_type_info datatype.
     * @param dtm
     * @return
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    @Override
    public DataType getRepresentedDataType() {
        if (dataType == null) {
            Matcher matcher = ARRAY_PATTERN.matcher(getTypeName());
            if (matcher.matches()) {
                int length = Integer.valueOf(matcher.group(1));
                DataType baseDt = parseDataType(matcher.group(2));
                dataType = new ArrayDataType(baseDt, length, baseDt.getLength());
            }
        }
        return dataType;
    }

}
