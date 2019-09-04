package ghidra.app.cmd.data.rtti;

import ghidra.program.model.data.DataType;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public interface Vftable {
    
    public static final Vftable INVALID = VtableModel.INVALID;

    /**
     * Returns the TypeInfo Model this vtable points to.
     * 
     * @return the pointed to TypeInfo Model.
     */
    public ClassTypeInfo getTypeInfo();

    /**
     * Checks if this is a valid vtable.
     * 
     * @return true if this is a valid vtable.
     */
    public boolean isValid();

    /**
     * Gets the correct DynamicDataType for this model.
     * 
     * @return the correct DataType or BadDataType if invalid.
     */
    public DataType getDataType();

    /**
     * Gets the addresses of this vtable's function tables.
     * 
     * @return the addresses of this vtable's function tables.
     */
    public Address[] getTableAddresses();

    /**
     * Gets the function tables in this vtable.
     * 
     * @return this vtable's function tables.
     */
    public Function[][] getFunctionTables();

    /**
     * Checks if this vtable contains the specified function.
     * 
     * @param function
     * @return true if this vtable contains the specified function.
     */
    public boolean containsFunction(Function function);
    
    /**
     * Gets the base ClassTypeInfo this vftable is for.
     * 
     * @return the base ClassTypeInfo
     */
    public ClassTypeInfo getBaseClassTypeInfo(int i);

}