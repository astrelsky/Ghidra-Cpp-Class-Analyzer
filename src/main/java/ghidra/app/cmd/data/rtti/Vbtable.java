package ghidra.app.cmd.data.rtti;

import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.address.Address;

public interface Vbtable {

    public static final String SYMBOL_NAME = "vbtable";

    /**
     * Gets the corrected start address of the vtable.
     * 
     * @return the correct start address or NO_ADDRESS if invalid.
     */
    public Address getAddress();

    /**
     * Gets the ptrdiff_t value within the offset array.
     * 
     * @param ordinal the offset ordinal.
     * @return the offset value.
     * @throws InvalidDataTypeException 
     */
    public long getOffset(int ordinal) throws InvalidDataTypeException;

    /**
     * Gets the whole ptrdiff_t array.
     * 
     * @return the whole ptrdiff_t array.
     * @throws InvalidDataTypeException
     */
    public long[] getOffsetArray() throws InvalidDataTypeException;

}