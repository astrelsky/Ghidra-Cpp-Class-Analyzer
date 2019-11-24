package ghidra.app.cmd.data.rtti.gcc;

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import ghidra.program.model.listing.Program;

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
        Set<VttModel> vtts = new LinkedHashSet<>();
        for (VtableModel vtable : builder.getVtableList()) {
            VttModel vtt = VtableUtils.getVttModel(program, vtable);
            if (vtt.isValid()) {
                vtts.add(vtt);
            }
        }
        for (VttModel vtt : builder.getVttList()) {
            assert vtts.contains(vtt) : vtt.getTypeInfo(0).getNamespace().getName(true);
        }
    }
}
