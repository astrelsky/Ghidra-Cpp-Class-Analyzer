package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.Ppc64TypeInfoProgramBuilder;

public abstract class Ppc64GccRttiTest extends GenericGccRttiTest {

	protected Ppc64GccRttiTest() {
		super();
	}


	@Override
    protected Ppc64TypeInfoProgramBuilder getProgramBuilder() throws Exception {
        return new Ppc64TypeInfoProgramBuilder();
    }
}
