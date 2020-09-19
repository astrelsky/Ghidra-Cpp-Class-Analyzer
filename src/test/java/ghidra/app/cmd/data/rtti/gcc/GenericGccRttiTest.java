package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.gcc.builder.AbstractTypeInfoProgramBuilder;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.OneShotAnalysisCommand;
import ghidra.app.plugin.prototype.GccRttiAnalyzer;
import ghidra.app.services.Analyzer;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractProgramBasedTest;

import cppclassanalyzer.analysis.gcc.GccCppClassAnalyzer;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public abstract class GenericGccRttiTest extends AbstractProgramBasedTest {

	protected AbstractTypeInfoProgramBuilder builder;

	protected GenericGccRttiTest() {
		super();
	}

	protected abstract AbstractTypeInfoProgramBuilder getProgramBuilder() throws Exception;

	@Override
	protected final Program getProgram() throws Exception {
		this.builder = getProgramBuilder();
		return builder.getProgram();
	}

	@Override
	protected void initialize() throws Exception {
		super.initialize();
		env.addPlugin(ClassTypeInfoManagerPlugin.class);
		AutoAnalysisManager man = AutoAnalysisManager.getAnalysisManager(program);
		// dispose it so the available analyzers are refreshed
		man.dispose();
		builder.init();
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
