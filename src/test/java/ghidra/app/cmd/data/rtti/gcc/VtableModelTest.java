package ghidra.app.cmd.data.rtti.gcc;

import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.builder.AbstractTypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.builder.Ppc64TypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

import org.junit.Test;

public class VtableModelTest extends GenericGccRttiTest {

	private void validationTest(AbstractTypeInfoProgramBuilder builder) throws Exception {
		for (VtableModel vtable : builder.getVtableList()) {
			assert Vtable.isValid(vtable) : vtable.getTypeInfo().getNamespace().getName(true);
		}
	}

	private void locationTest(AbstractTypeInfoProgramBuilder builder) throws Exception {
		ClassTypeInfoManager manager = builder.getManager();
		manager.sort(TaskMonitor.DUMMY);

		Set<Address> addresses = manager.getClassTypeInfoStream(true)
										.map(ClassTypeInfo::findVtable)
										.filter(Vtable::isValid)
										.map(Vtable::getAddress)
										.collect(Collectors.toSet());
		
		for (VtableModel vtable : builder.getVtableList()) {
			assert addresses.contains(vtable.getAddress())
				: vtable.getTypeInfo().getNamespace().getName(true);
		}
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
