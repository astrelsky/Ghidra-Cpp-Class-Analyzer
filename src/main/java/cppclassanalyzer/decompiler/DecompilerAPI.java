package cppclassanalyzer.decompiler;

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Disposable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheStats;

import cppclassanalyzer.decompiler.function.HighFunctionCall;
import cppclassanalyzer.decompiler.token.ClangNodeUtils;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

/**
 * A Decompiler API with more to offer than the
 * {@link ghidra.app.decompiler.flatapi.FlatDecompilerAPI FlatDecompilerAPI}
 */
public final class DecompilerAPI implements Disposable, AutoCloseable {

	private final PluginTool tool;
	private final DecompInterface decompiler;
	private Cache<Function, DecompileResults> cache;
	private TaskMonitor monitor;
	private int timeout;

	/**
	 * Constructs a new DecompilerAPI
	 * @param tool the current tool
	 */
	public DecompilerAPI(PluginTool tool) {
		this.tool = tool;
		this.decompiler = new DecompInterface();
		this.monitor = TaskMonitor.DUMMY;
	}

	/**
	 * Constructs a new DecompilerAPI
	 * @param program the current program
	 */
	public DecompilerAPI(Program program) {
		this(program, TaskMonitor.DUMMY, 0);
	}

	/**
	 * Constructs a new DecompilerAPI
	 * @param program the current program
	 * @param monitor the monitor to use for the decompiler
	 * @param timeout the timeout to use for the decompiler or &lt; 0 to use
	 * the default timeout provided by user settings.
	 */
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

	@Override
	public void dispose() {
		if (decompiler != null) {
			decompiler.dispose();
		}
	}

	@Override
	public void close() {
		dispose();
	}

	private DecompInterface setUpDecompiler(Program program) {

		// call it to get results
		if (!decompiler.openProgram(program)) {
			decompiler.dispose();
			throw new AssertException("Decompile Error: " + decompiler.getLastMessage());
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = tool != null ? tool.getService(OptionsService.class) : null;
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

	/**
	 * Get the current program opened in the decompiler
	 * @return the decompiler's opened program
	 */
	public Program getProgram() {
		return decompiler.getProgram();
	}

	/**
	 * Sets the program for the decompiler to use
	 * @param program to program to open in the decompiler
	 */
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

	/**
	 * Gets the tool
	 * @return the tool
	 */
	public PluginTool getTool() {
		return tool;
	}

	/**
	 * Gets the decompiler
	 * @return the decompiler
	 */
	public DecompInterface getDecompiler() {
		return decompiler;
	}

	/**
	 * Gets the decompiler timeout
	 * @return the decompiler timeout
	 */
	public int getTimeout() {
		return timeout;
	}

	/**
	 * Sets the decompiler timeout
	 * @param timeout the timeout
	 */
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	/**
	 * Sets the task monitor to use
	 * @param monitor the task monitor
	 */
	public void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	/**
	 * Gets a thread safe and unmodifiable view of the decompiler cache
	 * @return a map of the decompiler cache
	 */
	public Map<Function, DecompileResults> getCache() {
		return Collections.unmodifiableMap(cache.asMap());
	}

	/**
	 * Flushes the decompiler cache
	 */
	public void clearCache() {
		cache.invalidateAll();
	}

	/**
	 * Decompiles the provided function
	 * @param function the function to decompile
	 * @return the decompiled function
	 * @throws CancelledException if the decompilation is cancelled
	 */
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

	/**
	 * Gets all the {@link ClangStatement}s in the decompiled function
	 * @param function the function to decompile
	 * @return a list of all the functions statements
	 * @throws CancelledException if the decompilation is cancelled
	 */
	public List<ClangStatement> getClangStatements(Function function) throws CancelledException {
		DecompileResults results = decompileFunction(Objects.requireNonNull(function));
		return ClangNodeUtils.getClangStatements(results.getCCodeMarkup());
	}

	/**
	 * Gets the HighFunction for the decompiled function
	 * @param function the function to decompile
	 * @return the functions HighFunction
	 * @throws CancelledException if the decompilation is cancelled
	 */
	public HighFunction getHighFunction(Function function) throws CancelledException {
		DecompileResults results = decompileFunction(Objects.requireNonNull(function));
		return results.getHighFunction();
	}

	/**
	 * Gets a list of all the functions the decompiled function calls
	 * @param function the function to decompile
	 * @return a list of function calls
	 * @throws CancelledException if the decompilation is cancelled
	 */
	public List<HighFunctionCall> getFunctionCalls(Function function) throws CancelledException {
		DecompileResults results = decompileFunction(Objects.requireNonNull(function));
		return ClangNodeUtils.getClangFunctionCalls(results.getCCodeMarkup());
	}

	/**
	 * A convience method to get the corresponding Function for a function name
	 * @param token the function name
	 * @return the function
	 */
	public Function getFunction(ClangFuncNameToken token) {
		return DecompilerUtils.getFunction(getProgram(), Objects.requireNonNull(token));
	}

	/**
	 * Gets the decompiler cache stats
	 * @return the decompiler cache stats
	 */
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
}
