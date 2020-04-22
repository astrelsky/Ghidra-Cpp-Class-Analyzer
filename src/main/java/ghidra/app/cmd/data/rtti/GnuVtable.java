package ghidra.app.cmd.data.rtti;

import java.util.List;

import ghidra.program.model.data.DataType;

public interface GnuVtable extends Vtable {

	/**
	 * Gets the ptrdiff_t value within the base offset array.
	 *
	 * @param index the index in the vtable_prefix array.
	 * @param ordinal the offset ordinal.
	 * @return the offset value.
	 */
	long getOffset(int index, int ordinal);

	/**
	 * Gets the whole ptrdiff_t array.
	 *
	 * @return the whole ptrdiff_t array.
	 */
	long[] getBaseOffsetArray();

	/**
	 * Gets the whole ptrdiff_t array for the specified prefix index
	 *
	 * @param index the vtable prefix index
	 * @return the whole ptrdiff_t array
	 */
	long[] getBaseOffsetArray(int index);

	/**
	 * Gets the DataTypes that compose this Vtable
	 * 
	 * @return the list of DataTypes this Vtable is made of
	 */
	List<DataType> getDataTypes();
	
	default int getLength() {
		return getDataTypes().stream()
							 .mapToInt(DataType::getLength)
							 .sum();
	}
}