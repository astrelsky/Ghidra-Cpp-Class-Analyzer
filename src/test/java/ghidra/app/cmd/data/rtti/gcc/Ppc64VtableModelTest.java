package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.Ppc64TypeInfoProgramBuilder;

import org.junit.Test;

public final class Ppc64VtableModelTest extends VtableModelTest {

	@Override
    protected Ppc64TypeInfoProgramBuilder getProgramBuilder() throws Exception {
        return new Ppc64TypeInfoProgramBuilder();
    }

    @Test
    public void locationTest() throws Exception {
        doLocationTest();
    }

    @Test
    public void validationTest() throws Exception {
        doValidationTest();
    }
	
}
