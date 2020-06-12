package cppclassanalyzer.utils;

import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ConstantPropagationUtils {

	private ConstantPropagationUtils() {
	}

	public static ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		List<ConstantPropagationAnalyzer> analyzers =
			ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
		for (ConstantPropagationAnalyzer analyzer : analyzers) {
			if (analyzer.canAnalyze(program)) {
				return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
			}
		}
		return null;
	}

	public static SymbolicPropogator analyzeFunction(Function function, TaskMonitor monitor)
		throws CancelledException {
			Program program = function.getProgram();
			ConstantPropagationAnalyzer analyzer = getConstantAnalyzer(program);
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.setParamRefCheck(true);
			symEval.setReturnRefCheck(true);
			symEval.setStoredRefCheck(true);
			analyzer.flowConstants(program, function.getEntryPoint(), function.getBody(),
				symEval, monitor);
			return symEval;
	}

}