package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import org.junit.Test;

public class VttModelTest extends GenericGccRttiTest {

    @Test
    public void test() throws Exception {
        X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
        for (VttModel vtt : builder.getVttList()) {
            assert vtt.isValid();
        }
    }
}
