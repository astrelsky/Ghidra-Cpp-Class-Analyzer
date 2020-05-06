package ghidra.app.cmd.data.rtti.gcc;

import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import org.junit.Test;

public class VttModelTest extends GenericGccRttiTest {

	@Test
	public void validationTest() throws Exception {
		X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
		for (VttModel vtt : builder.getVttList()) {
			assert vtt.isValid();
		}
	}

	@Test
	public void locationTest() throws Exception {
		X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
		Program program = builder.getProgram();
		ClassTypeInfoManager manager = builder.getManager();
		manager.findVtables(TaskMonitor.DUMMY);
		Set<Address> addresses = builder.getVttStream()
										.map(VttModel::getAddress)
										.collect(Collectors.toSet());
		for (Vtable vtable : manager.getVtables()) {
			VttModel vtt = VtableUtils.getVttModel(program, (GnuVtable) vtable);
			if (vtt.isValid()) {
				assert addresses.remove(vtt.getAddress())
					: String.format("%s at %s is at the wrong address",
						vtt, vtt.getAddress());
			}
		}
		assert addresses.isEmpty() : Integer.toString(addresses.size())
			+ " vtts were not located";
	}
}
