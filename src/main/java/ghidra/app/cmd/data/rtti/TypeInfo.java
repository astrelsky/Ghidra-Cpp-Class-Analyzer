package ghidra.app.cmd.data.rtti;

import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Namespace;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.program.model.address.Address;

/**
 * Interface for modeling std::type_info and its derivatives.
 * <br>
 * All derived models are based on dwarf information from libstdc++.a
 */
public interface TypeInfo {

    static final TypeInfo INVALID = TypeInfoModel.INVALID;

    static final String SYMBOL_NAME = "typeinfo";

    /**
     * Gets name for the TypeInfo DataType Model
     */
    String getName();

    /**
     * Gets the namespace for this TypeInfo
     */
     Namespace getNamespace();

    /**
     * Gets The TypeInfo's typename string
     */
    String getTypeName();

    /**
     * Gets The TypeInfo's Identifier String ie "St9type_info"
     */
    String getIdentifier();

    /**
     * Gets corresponding structure for this TypeInfo Model
     */
    DataType getDataType();

    /**
     * Gets the DataType represented by this TypeInfo
     * @return the represented DataType
     */
    DataType getRepresentedDataType();

    /**
	 * Gets the address of this TypeInfo structure.
	 * 
     * @return the TypeInfo structure's address.
     */ 
    Address getAddress();

    /**
     * Checks if the TypeInfo is a valid type_info structure.
     * 
     * @return true if valid.
     */
    boolean isValid();

}