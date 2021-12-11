package ghidra.app.cmd.data.rtti.gcc;

import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExternalClassTypeInfoFactory {

	private ExternalClassTypeInfoFactory() {
	}

	public static ClassTypeInfo getExternalTypeInfo(Program program, Address address) {
		return new UnresolvedExternalTypeInfo(program, address);
	}

	private static class UnresolvedExternalTypeInfo implements ClassTypeInfo {

		private final Address address;
		private final String symbol;

		UnresolvedExternalTypeInfo(Program program, Address address) {
			this.address = address;
			Symbol s = program.getSymbolTable().getPrimarySymbol(address);
			this.symbol = s != null ? s.getName(true) : "";
		}

		@Override
		public String getName() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public Namespace getNamespace() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public String getTypeName() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public String getIdentifier() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public DataType getDataType() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public GhidraClass getGhidraClass() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public boolean hasParent() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public ClassTypeInfo[] getParentModels() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public Set<ClassTypeInfo> getVirtualParents() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public boolean isAbstract() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public Vtable getVtable() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

		@Override
		public Structure getClassDataType() {
			throw new UnresolvedClassTypeInfoException(address, symbol);
		}

	}
}
