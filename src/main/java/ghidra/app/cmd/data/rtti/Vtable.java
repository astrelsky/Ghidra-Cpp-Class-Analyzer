package ghidra.app.cmd.data.rtti;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;

public interface Vtable {

	public static final InvalidVtable NO_VTABLE = new InvalidVtable();

	public static boolean isValid(Vtable vtable) {
		return vtable != NO_VTABLE;
	}

	/**
	 * Returns the TypeInfo Model this vtable points to
	 * @return the pointed to TypeInfo Model
	 */
	public ClassTypeInfo getTypeInfo();

	/**
	 * Gets the addresses of this vtable's function tables
	 * @return the addresses of this vtable's function tables
	 */
	public Address[] getTableAddresses();

	/**
	 * Gets the address of the start of the vtable
	 * @return the address of the start of the vtable
	 */
	public Address getAddress();

	/**
	 * Gets the function tables in this vtable
	 * @return this vtable's function tables
	 */
	public Function[][] getFunctionTables();

	/**
	 * Checks if this vtable contains the specified function
	 * @param function the function to check for
	 * @return true if this vtable contains the specified function
	 */
	public boolean containsFunction(Function function);

	static class InvalidVtable implements GnuVtable {

		private static final String MESSAGE = "Invalid Vtable";

		private InvalidVtable() {
		}

		@Override
		public ClassTypeInfo getTypeInfo() {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public Address[] getTableAddresses() {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public Address getAddress() {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public Function[][] getFunctionTables() {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public boolean containsFunction(Function function) {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public long getOffset(int index, int ordinal) {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public List<DataType> getDataTypes() {
			throw new UnsupportedOperationException(MESSAGE);
		}

		@Override
		public List<VtablePrefix> getPrefixes() {
			throw new UnsupportedOperationException(MESSAGE);
		}
	}
}