package ghidra.app.cmd.data.rtti.gcc;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Exception thrown when the data for a dynamically linked __class_type_info
 * cannot be located.
 */
@SuppressWarnings("serial")
public class UnresolvedClassTypeInfoException extends RuntimeException {

	public UnresolvedClassTypeInfoException(Address address, String symbol) {
		super(
			String.format(
				"A base class at %s cannot be resolved because"
				+ " the data for the relocated symbol %s is missing", address, symbol)
		);
	}

	public UnresolvedClassTypeInfoException(Program program) {
		super("The ClassTypeInfo Archive for " + program.getName() + " could not be found");
	}

	public UnresolvedClassTypeInfoException(String msg) {
		super(msg);
	}
}