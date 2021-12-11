package cppclassanalyzer.cmd;

import java.util.Objects;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;

/**
 * BackgroundCommand to create an ExternalLocation
 */
public class CreateExternalSymbolBackgroundCmd extends BackgroundCommand {

	private final SymbolInfoProvider provider;
	private ExternalLocation location;

	/**
	 * Constructs a new CreateExternalSymbolBackgroundCmd
	 * @param type the archived type providing the symbol information
	 */
	public CreateExternalSymbolBackgroundCmd(ArchivedClassTypeInfo type) {
		this.provider = new TypeSymbolInfoProvider(type);
	}

	/**
	 * Constructs a new CreateExternalSymbolBackgroundCmd
	 * @param libName the library name
	 * @param symbol the symbol name
	 */
	public CreateExternalSymbolBackgroundCmd(String libName, String symbol) {
		this.provider = new RawSymbolInfoProvider(libName, symbol);
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if (!(obj instanceof Program)) {
			setStatusMsg("obj must be a program");
			return false;
		}
		Program program = (Program) obj;
		ExternalManager man = program.getExternalManager();
		if (!man.contains(provider.getLibraryName())) {
			setStatusMsg(provider.getLibraryName() + " is not an existing library");
			return false;
		}
		Library lib = man.getExternalLibrary(provider.getLibraryName());
		String symbol = provider.getSymbolName();
		Address address;
		if (provider instanceof TypeSymbolInfoProvider) {
			address = ((TypeSymbolInfoProvider) provider).getType().getExternalAddress(program);
		} else {
			address = null;
		}
		try {
			this.location = man.addExtLocation(lib, symbol, address, SourceType.IMPORTED, true);
		} catch (InvalidInputException e) {
			throw new AssertException(e);
		}
		return this.location != null;
	}

	/**
	 * Gets the created external location
	 * @return the created external location
	 */
	public ExternalLocation getExternalLocation() {
		return location;
	}

	private static interface SymbolInfoProvider {

		String getLibraryName();
		String getSymbolName();
	}

	private static class TypeSymbolInfoProvider implements SymbolInfoProvider {

		private final ArchivedClassTypeInfo type;

		private TypeSymbolInfoProvider(ArchivedClassTypeInfo type) {
			this.type = Objects.requireNonNull(type);
		}

		@Override
		public String getLibraryName() {
			return type.getProgramName();
		}

		@Override
		public String getSymbolName() {
			return type.getSymbolName();
		}

		private ArchivedClassTypeInfo getType() {
			return type;
		}
	}

	private static class RawSymbolInfoProvider implements SymbolInfoProvider {

		private final String libName;
		private final String symbol;

		private RawSymbolInfoProvider(String libName, String symbol) {
			this.libName = Objects.requireNonNull(libName);
			this.symbol = Objects.requireNonNull(symbol);
		}

		@Override
		public String getLibraryName() {
			return libName;
		}

		@Override
		public String getSymbolName() {
			return symbol;
		}
	}

}
