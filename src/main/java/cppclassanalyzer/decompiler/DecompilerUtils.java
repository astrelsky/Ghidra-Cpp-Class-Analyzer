package cppclassanalyzer.decompiler;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

public class DecompilerUtils extends ghidra.app.decompiler.component.DecompilerUtils {

	private DecompilerUtils() {
	}

	public static DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(program)) {
			decompInterface.dispose();
			throw new AssertException("Decompile Error: " + decompInterface.getLastMessage());
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service =
			CppClassAnalyzerUtils.getTool(program).getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public static DecompileResults decompileFunction(Function f, DecompInterface decompInterface,
			TaskMonitor monitor) {
		return decompileFunction(f, decompInterface, monitor,
			decompInterface.getOptions().getDefaultTimeout());
	}

	public static DecompileResults decompileFunction(Function f, DecompInterface decompInterface,
			TaskMonitor monitor, int timeout) {
		return decompInterface.decompileFunction(f, timeout, monitor);
	}

	public static List<ClangStatement> getClangStatements(Function f, TaskMonitor monitor)
			throws CancelledException {
		return getClangStatements(f, monitor, 0);
	}

	public static List<ClangStatement> getClangStatements(Function f, TaskMonitor monitor,
			int timeout) throws CancelledException {
		Program program = Objects.requireNonNull(f).getProgram();
		DecompInterface decompInterface = setUpDecompiler(program);
		try {
			DecompileResults results;
			if (timeout > 0) {
				results = decompileFunction(f, decompInterface, monitor, timeout);
			} else {
				results = decompileFunction(f, decompInterface, monitor);
			}
			monitor.checkCanceled();
			ClangNodeIterator it = new ClangNodeIterator(results.getCCodeMarkup());
			return CollectionUtils.asStream(it)
				.filter(ClangTokenGroup.class::isInstance)
				.map(ClangTokenGroup.class::cast)
				.map(ClangNodeIterator::new)
				.flatMap(CollectionUtils::asStream)
				.filter(ClangStatement.class::isInstance)
				.map(ClangStatement.class::cast)
				.collect(Collectors.toList());
		} finally {
			decompInterface.dispose();
		}
	}

	public static HighFunction getHighFunction(Function f, TaskMonitor monitor)
		throws CancelledException{
			Program program = Objects.requireNonNull(f).getProgram();
			DecompInterface decompInterface = setUpDecompiler(program);
			try {
				DecompileResults results = decompileFunction(f, decompInterface, monitor);
				monitor.checkCanceled();
				return results.getHighFunction();
			} finally {
				decompInterface.dispose();
			}
	}

	public static List<HighParam> getParameters(Function f, TaskMonitor monitor)
			throws CancelledException {
		HighFunction hf = getHighFunction(f, monitor);
		LocalSymbolMap locals = hf.getLocalSymbolMap();
		if (locals.getNumParams() == 0) {
			return Collections.emptyList();
		}
		return IntStream.range(0, locals.getNumParams())
			.mapToObj(locals::getParam)
			.collect(Collectors.toList());
	}

}