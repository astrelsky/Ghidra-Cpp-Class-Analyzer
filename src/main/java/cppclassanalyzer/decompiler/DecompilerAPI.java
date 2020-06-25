package cppclassanalyzer.decompiler;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.Disposable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheStats;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

public final class DecompilerAPI implements Disposable {

	private final PluginTool tool;
	private final DecompInterface decompiler;
	private Cache<Function, DecompileResults> cache;
	private TaskMonitor monitor;
	private int timeout;

	public DecompilerAPI(PluginTool tool) {
		this.tool = tool;
		this.decompiler = new DecompInterface();
		this.monitor = TaskMonitor.DUMMY;
	}

	public DecompilerAPI(Program program) {
		this(program, TaskMonitor.DUMMY, 0);
	}

	public DecompilerAPI(Program program, TaskMonitor monitor, int timeout) {
		this.tool = CppClassAnalyzerUtils.getTool(program);
		this.decompiler = new DecompInterface();
		setUpDecompiler(program);
		this.cache = buildCache(decompiler.getOptions().getCacheSize());
		this.monitor = monitor;
		if (timeout >= 0) {
			this.timeout = timeout;
		} else {
			this.timeout = decompiler.getOptions().getDefaultTimeout();
		}
	}

	public DecompInterface setUpDecompiler(Program program) {

		// call it to get results
		if (!decompiler.openProgram(program)) {
			decompiler.dispose();
			throw new AssertException("Decompile Error: " + decompiler.getLastMessage());
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = tool.getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompiler.setOptions(options);

		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");

		return decompiler;
	}

	@Override
	public void dispose() {
		if (decompiler != null) {
			decompiler.dispose();
		}
	}

	public Program getProgram() {
		return decompiler.getProgram();
	}

	public void setProgram(Program program) {
		Program currentProgram = getProgram();
		if (currentProgram == null || !currentProgram.equals(program)) {
			if (currentProgram != null) {
				decompiler.closeProgram();
			}
			setUpDecompiler(program);
			this.cache = buildLargeCache();
		}
	}

	public PluginTool getTool() {
		return tool;
	}

	public DecompInterface getDecompiler() {
		return decompiler;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	public Map<Function, DecompileResults> getCache() {
		return Collections.unmodifiableMap(cache.asMap());
	}

	public void clearCache() {
		cache.invalidateAll();
	}

	public DecompileResults decompileFunction(Function function) throws CancelledException {
		DecompileResults results = cache.getIfPresent(Objects.requireNonNull(function));
		if (results != null) {
			return results;
		}
		results = decompiler.decompileFunction(function, timeout, monitor);
		monitor.checkCanceled();
		cache.put(function, results);
		return results;
	}

	public List<ClangStatement> getClangStatements(Function function) throws CancelledException {
		DecompileResults results = decompileFunction(Objects.requireNonNull(function));
		ClangNodeIterator it = new ClangNodeIterator(results.getCCodeMarkup());
		return CollectionUtils.asStream(it)
				.filter(ClangTokenGroup.class::isInstance)
				.map(ClangTokenGroup.class::cast)
				.map(ClangNodeIterator::new)
				.flatMap(CollectionUtils::asStream)
				.filter(ClangStatement.class::isInstance)
				.map(ClangStatement.class::cast)
				.collect(Collectors.toList());
	}

	public HighFunction getHighFunction(Function function) throws CancelledException {
		DecompileResults results = decompileFunction(Objects.requireNonNull(function));
		return results.getHighFunction();
	}

	public List<HighParam> getParameters(Function function) throws CancelledException {
		HighFunction hf = getHighFunction(Objects.requireNonNull(function));
		LocalSymbolMap locals = hf.getLocalSymbolMap();
		if (locals.getNumParams() == 0) {
			return Collections.emptyList();
		}
		return IntStream.range(0, locals.getNumParams())
				.mapToObj(locals::getParam)
				.collect(Collectors.toList());
	}

	public Function getFunction(ClangFuncNameToken token) {
		return DecompilerUtils.getFunction(getProgram(), Objects.requireNonNull(token));
	}

	public CacheStats getCacheStats() {
		return cache.stats();
	}

	private static Cache<Function, DecompileResults> buildCache(int cacheSize) {
		return CacheBuilder.newBuilder()
           .softValues()
           .maximumSize(cacheSize)
           .build();
	}

	private static Cache<Function, DecompileResults> buildLargeCache() {
		return CacheBuilder.newBuilder()
           .softValues()
           .maximumSize(100)
           .build();
	}

	public void invalidateCache() {
		cache.invalidateAll();
	}

}
