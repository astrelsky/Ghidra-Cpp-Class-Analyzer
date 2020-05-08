package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;

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
			&& !GnuUtils.isExternal(program, baseAddress)) {
				ClassTypeInfo parent = manager.getType(baseAddress);
				if (parent != null) {
					return new ClassTypeInfo[] { parent };
				}
		}
		return new ClassTypeInfo[] { manager.getExternalClassTypeInfo(baseAddress) };
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		ClassTypeInfo[] parents = getParentModels();
		return parents[0].getVirtualParents();
	}

}
