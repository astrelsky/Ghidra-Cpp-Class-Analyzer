package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;

public abstract class X86GccRttiTest extends GenericGccRttiTest {
	
	protected X86GccRttiTest() {
		super();
	}


	@Override
    protected X86TypeInfoProgramBuilder getProgramBuilder() throws Exception {
        return new X86TypeInfoProgramBuilder();
    }
}
