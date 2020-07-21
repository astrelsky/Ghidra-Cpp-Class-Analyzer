package ghidra.app.cmd.data.rtti;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;

public interface GnuVtable extends Vtable {

	public static final String PURE_VIRTUAL_FUNCTION_NAME = "__cxa_pure_virtual";

	/**
	 * Gets the ptrdiff_t value within the base offset array.
	 *
	 * @param index the index in the vtable_prefix array.
	 * @param ordinal the offset ordinal.
	 * @return the offset value.
	 */
	long getOffset(int index, int ordinal);

	/**
	 * Gets the DataTypes that compose this Vtable
	 *
	 * @return the list of DataTypes this Vtable is made of
	 */
	List<DataType> getDataTypes();

	/**
	 * Gets the vtable prefixes that compose this vtable
	 *
	 * @return the list of vtable prefixes
	 */
	List<VtablePrefix> getPrefixes();

	default int getLength() {
		return getDataTypes().stream()
							 .mapToInt(DataType::getLength)
							 .sum();
	}

	interface VtablePrefix {

		/**
		 * Gets the whole ptrdiff_t array.
		 *
		 * @return the whole ptrdiff_t array.
		 */
		List<Long> getOffsets();
		List<Function> getFunctionTable();
		List<DataType> getDataTypes();
		Address getAddress();
	}
}
