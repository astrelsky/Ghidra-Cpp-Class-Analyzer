package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Collections;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.exception.AssertException;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ExternalClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

/**
 * Base Model for __si_class_type_info and its derivatives.
 */
abstract class AbstractSiClassTypeInfoModel extends AbstractClassTypeInfoModel {

	protected AbstractSiClassTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	private static Address getBaseTypeAddress(Program program, Address address) {
		Address pointerAddress = address.add(program.getDefaultPointerSize() << 1);
		Address result = getAbsoluteAddress(program, pointerAddress);
		return result != null ? result : Address.NO_ADDRESS;
	}

	@Override
	public boolean hasParent() {
		return true;
	}

	@Override
	public ClassTypeInfo[] getParentModels() {
		Address baseAddress = getBaseTypeAddress(program, address);
		if (!baseAddress.equals(Address.NO_ADDRESS)
			&& program.getMemory().getBlock(baseAddress).isInitialized()) {
				ClassTypeInfo parent = manager.getClassTypeInfo(baseAddress);
				if (parent != null) {
					return new ClassTypeInfo[] { parent };
				}
		}
		RelocationTable table = program.getRelocationTable();
		Relocation reloc = table.getRelocation(baseAddress);
		if (reloc == null) {
			reloc = table.getRelocation(address.add(program.getDefaultPointerSize() << 1));
		}
		if (reloc != null && reloc.getSymbolName() != null) {
			TypeInfo type = TypeInfoUtils.getExternalTypeInfo(program, reloc);
			if (type instanceof ClassTypeInfo) {
				return new ClassTypeInfo[]{
					(ClassTypeInfo) type
				};
			}
		}
		StringBuilder builder = new StringBuilder("SiClassTypeInfo at ");
		builder.append(address.toString())
			   .append(" has an invalid parent located at ")
			   .append(reloc != null ? "relocation "+reloc.getAddress().toString()
			   	: baseAddress.toString());
		throw new AssertException(builder.toString());
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		ClassTypeInfo[] parents = getParentModels();
		if (parents[0] instanceof ExternalClassTypeInfo) {
			// TODO need more data to know if this is acceptable or not
			return Collections.emptySet();
		}
		return parents[0].getVirtualParents();
	}

}
