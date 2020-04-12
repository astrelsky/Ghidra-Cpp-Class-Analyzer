package ghidra.app.cmd.data.rtti.gcc;

import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ExternalClassTypeInfo implements ClassTypeInfo {

	private final Program program;
	private final Relocation reloc;
	
	public ExternalClassTypeInfo(Program program, Relocation reloc) {
		this.program = program;
		this.reloc = reloc;
		if (reloc.getSymbolName() == null) {
			throw new AssertException(
				String.format("External Relocation at %s has no symbol name", reloc.getAddress()));
		}
	}

	@Override
	public String getName() {
		Namespace ns = TypeInfoUtils.getNamespaceFromTypeName(program, reloc.getSymbolName());
		return ns.getName();
	}

	@Override
	public Namespace getNamespace() {
		return TypeInfoUtils.getNamespaceFromTypeName(program, reloc.getSymbolName());
	}

	@Override
	public String getTypeName() {
		return reloc.getSymbolName();
	}

	@Override
	public String getIdentifier() {
		throw new UnsupportedOperationException(getClass().getSimpleName()+" has no identifier");
	}

	@Override
	public DataType getDataType() {
		// This successfully prevents its creation in the listing
		return null;
	}

	@Override
	public Address getAddress() {
		return reloc.getAddress();
	}

	@Override
	public GhidraClass getGhidraClass() {
		Namespace ns = getNamespace();
		if (ns instanceof GhidraClass) {
			return (GhidraClass) ns;
		}
		try {
			return NamespaceUtils.convertNamespaceToClass(ns);
		} catch (InvalidInputException e) {
			// should not occur
			throw new AssertException(e);
		}
	}

	@Override
	public boolean hasParent() {
		return false;
	}

	@Override
	public ClassTypeInfo[] getParentModels() {
		throw new UnsupportedOperationException(
			"Cannot determine the parent models of an "+getClass().getSimpleName());
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		throw new UnsupportedOperationException(
			"Cannot determine the virtual parent models of an "+getClass().getSimpleName());
	}

	@Override
	public boolean isAbstract() {
		throw new UnsupportedOperationException(
			String.format("Cannot determine if an %s is abstract", getClass().getSimpleName()));
	}

	@Override
	public Vtable getVtable(TaskMonitor monitor) throws CancelledException {
		return Vtable.NO_VTABLE;
	}

	@Override
	public Structure getClassDataType() {
		return ClassTypeInfoUtils.getPlaceholderStruct(this, program.getDataTypeManager());
	}

	@Override
	public String getUniqueTypeName() {
		throw new UnsupportedOperationException(
			"Cannot create a unique type name for an "+getClass().getSimpleName());
	}

}