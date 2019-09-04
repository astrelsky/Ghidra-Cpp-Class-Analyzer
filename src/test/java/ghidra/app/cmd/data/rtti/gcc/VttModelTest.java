package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class VttModelTest extends AbstractGenericTest {

    @Test
    public void test() throws Exception {
        X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
        for (VttModel vtt : builder.getVttList()) {
            assert vtt.isValid();
        }
    }
}
