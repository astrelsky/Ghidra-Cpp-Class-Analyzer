package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.OneShotAnalysisCommand;
import ghidra.app.plugin.prototype.GccRttiAnalyzer;
import ghidra.app.services.Analyzer;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

import cppclassanalyzer.analysis.gcc.GccCppClassAnalyzer;

public class GenericGccRttiTest extends AbstractGhidraHeadedIntegrationTest {

	protected GenericGccRttiTest() {
		super();
	}

	void runGccRttiAnalyzer(Program program) throws Exception {
		runAnalyzer(program, GccRttiAnalyzer.ANALYZER_NAME);
	}

	void runClassAnalyzer(Program program) throws Exception {
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
