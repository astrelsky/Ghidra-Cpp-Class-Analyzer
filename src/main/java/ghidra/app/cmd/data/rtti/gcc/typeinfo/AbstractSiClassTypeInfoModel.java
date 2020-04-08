package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.exception.AssertException;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;

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
		TypeInfo parent = null;
		if (!baseAddress.equals(Address.NO_ADDRESS)
			&& program.getMemory().getBlock(baseAddress).isInitialized()) {
				parent = TypeInfoFactory.getTypeInfo(program, baseAddress);
				if (parent instanceof ClassTypeInfo) {
					return new ClassTypeInfo[] {
						(ClassTypeInfo) parent
					};
				}
        }
        RelocationTable table = program.getRelocationTable();
        Relocation reloc = table.getRelocation(baseAddress);
        if (reloc != null && reloc.getSymbolName() != null) {
            parent = TypeInfoUtils.getExternalTypeInfo(program, reloc);
            if (parent instanceof ClassTypeInfo) {
                return new ClassTypeInfo[]{
                    (ClassTypeInfo) parent
                };
            }
		}
		StringBuilder builder = new StringBuilder("SiClassTypeInfo at ");
		builder.append(address.toString())
			   .append(" has an invalid parent ");
		if (parent == null) {
			builder.append("located at ")
				   .append(reloc != null ? "relocation "+reloc.getAddress().toString()
				   		   : baseAddress.toString());
		} else {
			if (!(parent instanceof ClassTypeInfo)) {
			   builder.append("Non __class_type_info ");
			}
			builder.append(parent.toString());
		}
		throw new AssertException(builder.toString());
    }

    @Override
    public Set<ClassTypeInfo> getVirtualParents() {
        ClassTypeInfo[] parents = getParentModels();
        return parents[0].getVirtualParents();
    }

}
