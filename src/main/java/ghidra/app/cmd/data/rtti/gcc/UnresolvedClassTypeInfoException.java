package ghidra.app.cmd.data.rtti.gcc;

import ghidra.program.model.address.Address;

/**
 * Exception thrown when the data for a dynamically linked __class_type_info
 * cannot be located.
 */
@SuppressWarnings("serial")
public class UnresolvedClassTypeInfoException extends RuntimeException {

	private final Address address;
	private final String missingSymbol;

	public UnresolvedClassTypeInfoException(Address address, String symbol) {
		super();
		this.address = address;
		this.missingSymbol = symbol;
	}

	@SuppressWarnings("unused")
	@Override
	public String getMessage() {
		if (this == null) {
			return super.getMessage();
		}
		return String.format(
			"A base class at %s cannot be resolved because"
			+" the data for the relocated symbol %s is missing", address, missingSymbol);
	}
}