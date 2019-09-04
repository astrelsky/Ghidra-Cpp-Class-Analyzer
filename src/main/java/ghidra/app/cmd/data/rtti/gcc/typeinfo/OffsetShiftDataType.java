package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.AbstractIntegerDataType;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.isLLP64;

public class OffsetShiftDataType extends AbstractIntegerDataType {

    private final static String NAME = "offset_shift";
    private final static String DESCRIPTION = "Signed Integer (compiler-specific size)";

    /** A statically defined LongDataType instance.*/
    public final static OffsetShiftDataType dataType = new OffsetShiftDataType();

    private static final String C_SIGNED_LONG = "long";

    public OffsetShiftDataType() {
        this(null);
    }

    public OffsetShiftDataType(DataTypeManager dtm) {
        super(NAME, true, dtm);
    }

    /**
     * @see ghidra.program.model.data.DataType#getLength()
     */
    public int getLength() {
        DataOrganization org = getDataOrganization();
        return isLLP64(getDataTypeManager()) ? (org.getLongLongSize() - 1)
            : (org.getLongSize() - 1);
    }

    /**
     * @see ghidra.program.model.data.DataType#isDynamicallySized()
     */
    @Override
    public boolean isDynamicallySized() {
        return true;
    }

    /**
     * 
     * @see ghidra.program.model.data.DataType#getDescription()
     */
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getCDeclaration() {
        return C_SIGNED_LONG;
    }

    @Override
    public AbstractIntegerDataType getOppositeSignednessDataType() {
        return null;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        if (dtm == getDataTypeManager()) {
            return this;
        }
        return new OffsetShiftDataType(dtm);
    }

    @Override
    public String getCTypeDeclaration(DataOrganization dataOrganization) {
        return null; // this datatype is faked as a long by g++.
    }
}