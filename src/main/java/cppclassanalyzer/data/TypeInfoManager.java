package cppclassanalyzer.data;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.program.model.address.Address;

/**
 * Manager for {@link TypeInfo}
 */
public interface TypeInfoManager {

	/**
	 * Get the TypeInfo at the address
	 * @param address the address of the TypeInfo
	 * @return the TypeInfo at the specified address or null if none exists.
	 * @throws UnresolvedClassTypeInfoException if this type requires a copy relocation
	 * which cannot be resolved.
	 */
	TypeInfo getTypeInfo(Address address) throws UnresolvedClassTypeInfoException;

	/**
	 * Checks if a valid TypeInfo is located at the address in the program.
	 * @param address the address of the TypeInfo
	 * @return true if the data is a valid TypeInfo
	 */
	boolean isTypeInfo(Address address);

}
