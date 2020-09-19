package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;

import org.junit.Test;

public final class X86VtableModelTest extends VtableModelTest {

	@Override
    protected X86TypeInfoProgramBuilder getProgramBuilder() throws Exception {
        return new X86TypeInfoProgramBuilder();
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
