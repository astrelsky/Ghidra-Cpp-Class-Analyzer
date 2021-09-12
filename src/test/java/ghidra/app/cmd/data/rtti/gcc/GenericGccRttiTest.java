package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.AbstractTypeInfoProgramBuilder;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.OneShotAnalysisCommand;
import ghidra.app.plugin.prototype.GccRttiAnalyzer;
import ghidra.app.services.Analyzer;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

import cppclassanalyzer.analysis.gcc.GccCppClassAnalyzer;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public abstract class GenericGccRttiTest extends AbstractGhidraHeadlessIntegrationTest {

	protected AbstractTypeInfoProgramBuilder builder;
	protected Program program;

	protected GenericGccRttiTest() {
	}

	protected abstract AbstractTypeInfoProgramBuilder getProgramBuilder() throws Exception;

	protected final Program getProgram() throws Exception {
		return builder.getProgram();
	}

	protected void initialize() throws Exception {
		builder = getProgramBuilder();
		builder.init();
		builder.startTransaction();
		program = builder.getProgram();
	}

	public final void tearDown() throws Exception {
		builder.endTransaction();
		builder.dispose();
	}

	protected final ProgramClassTypeInfoManager getManager() {
		return CppClassAnalyzerUtils.getManager(program);
	}

	protected final void runGccRttiAnalyzer(Program program) throws Exception {
		runAnalyzer(program, GccRttiAnalyzer.ANALYZER_NAME);
	}

	protected final void runClassAnalyzer(Program program) throws Exception {
		runAnalyzer(program, GccCppClassAnalyzer.ANALYZER_NAME);
	}

	private void runAnalyzer(Program program, String name) throws Exception {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		Analyzer analyzer = manager.getAnalyzer(name);
		OneShotAnalysisCommand cmd = new OneShotAnalysisCommand(
			analyzer, program.getMemory(), manager.getMessageLog());
		cmd.applyTo(program);
	}
}
