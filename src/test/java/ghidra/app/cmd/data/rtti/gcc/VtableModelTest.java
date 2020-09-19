package ghidra.app.cmd.data.rtti.gcc;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.model.address.Address;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;

public abstract class VtableModelTest extends GenericGccRttiTest {

	protected final void doValidationTest() throws Exception {
		initialize();
		List<GnuVtable> vtables = builder.getVtableList();
		for (GnuVtable vtable : vtables) {
			assert Vtable.isValid(vtable) : vtable.getTypeInfo().getNamespace().getName(true);
		}
		ProgramClassTypeInfoManager manager = getManager();
		vtables.forEach(manager::resolve);
	}

	protected final void doLocationTest() throws Exception {
		initialize();
		runGccRttiAnalyzer(program);
		Set<Address> addresses = builder.getVtableStream()
			.map(Vtable::getAddress)
			.collect(Collectors.toSet());
		for (Vtable vtable : getManager().getVtables()) {
			assert addresses.remove(vtable.getAddress())
				: String.format("Vtable for %s was incorrectly located. It should not be at %s",
					vtable.getTypeInfo().getName(), vtable.getAddress());
		}
		assert addresses.isEmpty() : Integer.toString(addresses.size())
			+" vtables were not located";
	}
}
