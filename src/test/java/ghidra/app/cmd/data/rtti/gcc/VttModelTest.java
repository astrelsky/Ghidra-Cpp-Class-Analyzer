package ghidra.app.cmd.data.rtti.gcc;

import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.model.address.Address;

import org.junit.Test;

public class VttModelTest extends X86GccRttiTest {

	@Test
	public void validationTest() throws Exception {
		initialize();
		for (VttModel vtt : builder.getVttList()) {
			assert vtt.isValid();
		}
	}

	@Test
	public void locationTest() throws Exception {
		initialize();
		runGccRttiAnalyzer(program);
		Set<Address> addresses = builder.getVttStream()
			.map(VttModel::getAddress)
			.collect(Collectors.toSet());
		for (Vtable vtable : getManager().getVtables()) {
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
