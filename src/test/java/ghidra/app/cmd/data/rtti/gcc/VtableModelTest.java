package ghidra.app.cmd.data.rtti.gcc;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.builder.AbstractTypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.builder.Ppc64TypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

import org.junit.Test;

public class VtableModelTest extends GenericGccRttiTest {

	private void validationTest(AbstractTypeInfoProgramBuilder builder) throws Exception {
		List<GnuVtable> vtables = builder.getVtableList();
		for (GnuVtable vtable : vtables) {
			assert Vtable.isValid(vtable) : vtable.getTypeInfo().getNamespace().getName(true);
		}
		ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(builder.getProgram());
		vtables.forEach(manager::resolve);
	}

	private void locationTest(AbstractTypeInfoProgramBuilder builder) throws Exception {
		ProgramClassTypeInfoManager manager = builder.getManager();
		manager.findVtables(TaskMonitor.DUMMY);
		Set<Address> addresses = builder.getVtableStream()
			.map(Vtable::getAddress)
			.collect(Collectors.toSet());
		for (Vtable vtable : manager.getVtables()) {
			assert addresses.remove(vtable.getAddress())
				: String.format("Vtable for %s was incorrectly located. It should not be at %s",
					vtable.getTypeInfo().getName(), vtable.getAddress());
		}
		assert addresses.isEmpty() : Integer.toString(addresses.size())
			+" vtables were not located";
	}

	@Test
	public void defaultValidationTest() throws Exception {
		X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
		validationTest(builder);
	}

	@Test
	public void defaultLocationTest() throws Exception {
		X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
		locationTest(builder);
	}

	@Test
	public void ppc64LocationTest() throws Exception {
		Ppc64TypeInfoProgramBuilder builder = new Ppc64TypeInfoProgramBuilder();
		locationTest(builder);
	}

	@Test
	public void ppc64ValidationTest() throws Exception {
		Ppc64TypeInfoProgramBuilder builder = new Ppc64TypeInfoProgramBuilder();
		validationTest(builder);
	}
}
