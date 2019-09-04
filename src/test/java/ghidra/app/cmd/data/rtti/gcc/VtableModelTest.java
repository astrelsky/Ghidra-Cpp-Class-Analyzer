package ghidra.app.cmd.data.rtti.gcc;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.rtti.gcc.builder.AbstractTypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.builder.Ppc64TypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import org.junit.Test;

public class VtableModelTest extends AbstractGenericTest {

    public void test(AbstractTypeInfoProgramBuilder builder) throws Exception {
        for (VtableModel vtable : builder.getVtableList()) {
            assert vtable.isValid();
        }
    }

    @Test
    public void defaultTest() throws Exception {
        X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
        test(builder);
    }

    @Test
    public void ppc64Test() throws Exception {
        Ppc64TypeInfoProgramBuilder builder = new Ppc64TypeInfoProgramBuilder();
        test(builder);
    }
}
