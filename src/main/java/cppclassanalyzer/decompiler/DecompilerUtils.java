package cppclassanalyzer.decompiler;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import com.google.common.cache.Cache;

import cppclassanalyzer.decompiler.token.ClangNodeUtils;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public class DecompilerUtils extends ghidra.app.decompiler.component.DecompilerUtils {

	private static final Map<Program, Map<Function, DecompileResults>> caches = new HashMap<>();

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

	public static DecompileResults decompileFunction(Function f, TaskMonitor monitor, int timeout) {
		Program program = f.getProgram();
		Map<Function, DecompileResults> cache = getDecompilerCache(program);
		if (cache.containsKey(f)) {
			return cache.get(f);
		}
		DecompInterface decompInterface = setUpDecompiler(program);
		try {
			DecompileResults results;
			if (timeout > 0) {
				results = decompileFunction(f, decompInterface, monitor, timeout);
			} else {
				results = decompileFunction(f, decompInterface, monitor);
			}
			cache.put(f, results);
			return results;
		} finally {
			decompInterface.dispose();
		}
	}

	public static DecompileResults decompileFunction(Function f, DecompInterface decompInterface,
			TaskMonitor monitor) {
		return decompileFunction(f, decompInterface, monitor,
			decompInterface.getOptions().getDefaultTimeout());
	}

	public static DecompileResults decompileFunction(Function f, DecompInterface decompInterface,
			TaskMonitor monitor, int timeout) {
		if (caches.containsKey(f.getProgram())) {
			Map<Function, DecompileResults> cache = caches.get(f.getProgram());
			if (cache.containsKey(f)) {
				return cache.get(f);
			}
		}
		return decompInterface.decompileFunction(f, timeout, monitor);
	}

	public static List<ClangStatement> getClangStatements(Function f, TaskMonitor monitor)
			throws CancelledException {
		return getClangStatements(f, monitor, 0);
	}

	public static List<ClangStatement> getClangStatements(Function f, TaskMonitor monitor,
			int timeout) throws CancelledException {
		DecompileResults results = decompileFunction(f, monitor, timeout);
		monitor.checkCanceled();
		return ClangNodeUtils.getClangStatements(results.getCCodeMarkup());
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

	public static Map<Function, DecompileResults> getDecompilerCache(Program program) {
		// private DecompilerController controller;
		if (caches.containsKey(program)) {
			return caches.get(program);
		}
		return getDecompilerCache(CppClassAnalyzerUtils.getTool(program));
	}

	private static DecompilerController getController(DecompilerProvider provider)
			throws Exception {
		Field field = DecompilerProvider.class.getDeclaredField("controller");
		field.setAccessible(true);
		DecompilerController controller = (DecompilerController) field.get(provider);
		field.setAccessible(false);
		return controller;
	}

	@SuppressWarnings("unchecked")
	private static Map<Function, DecompileResults> getCache(DecompilerController controller)
			throws Exception {
		Field field = DecompilerController.class.getDeclaredField("decompilerCache");
		field.setAccessible(true);
		Cache<Function, DecompileResults> cache =
			(Cache<Function, DecompileResults>) field.get(controller);
		field.setAccessible(false);
		return cache.asMap();
	}

	public static Map<Function, DecompileResults> getDecompilerCache(PluginTool tool) {
		DecompilerProvider provider =
			(DecompilerProvider) tool.getComponentProvider("Decompiler");
		if (provider == null) {
			return null;
		}
		try {
			DecompilerController controller = getController(provider);
			return getCache(controller);
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}
}
