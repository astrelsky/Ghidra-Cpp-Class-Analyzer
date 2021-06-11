package cppclassanalyzer.analysis;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.analysis.cmd.AbstractConstructorAnalysisCmd;
import cppclassanalyzer.cmd.ApplyVtableDefinitionsBackgroundCmd;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.vtable.ArchivedVtable;
import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public abstract class AbstractCppClassAnalyzer extends AbstractAnalyzer {

	private static final String DESCRIPTION =
		"This analyzer analyzes RTTI metadata to recreate classes and their functions";

	private static final String OPTION_VTABLE_ANALYSIS_NAME = "Locate Constructors";
	private static final boolean OPTION_DEFAULT_VTABLE_ANALYSIS = false;
	private static final String OPTION_VTABLE_ANALYSIS_DESCRIPTION =
		"Turn on to search for Constructors/Destructors.\n" +
		"WARNING: This can take a SIGNIFICANT Amount of Time!\n" +
		"         Turned off by default" + "\n";

	private static final String OPTION_ARCHIVED_DATA_NAME = "Use Archived RTTI Data";
	private static final boolean OPTION_DEFAULT_ARCHIVED_DATA = true;
	private static final String OPTION_ARCHIVED_DATA_DESCRIPTION =
		"Use open archives to apply virtual function definitions and structures.\n"
		+ "This will replace previously defined structures and function definitions.";

	private static final String OPTION_NAME_DECOMPILER_TIMEOUT_SECS =
		"Analysis Decompiler Timeout (sec)";
	private static final String OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS =
		"Set timeout in seconds for analyzer decompiler calls.";
	private static final int OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS = 30;

	private boolean constructorAnalysisOption;
	private boolean useArchivedData;
	private int decompilerTimeout;

	protected Program program;
	protected TaskMonitor monitor;

	private ProgramClassTypeInfoManager manager;

	protected AbstractConstructorAnalysisCmd constructorAnalyzer;

	protected MessageLog log;

	/**
	 * Constructs an AbstractCppClassAnalyzer.
	 *
	 * @param name The name of the analyzer
	 *
	 */
	public AbstractCppClassAnalyzer(String name) {
		super(name, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setDefaultEnablement(true);
		setPrototype();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return CppClassAnalyzerUtils.getManager(program) != null;
	}

	protected abstract boolean hasVtt();
	protected abstract void init();
	protected abstract boolean analyzeVftable(ClassTypeInfo type);
	protected abstract boolean analyzeConstructor(ClassTypeInfo type);
	protected abstract boolean isDestructor(Function function);

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		this.manager = CppClassAnalyzerUtils.getManager(program);
		if (manager == null) {
			return false;
		}
		init();
		if (manager == null) {
			return false;
		}
		try {
			if (manager == null) {
				return false;
			}
			repairInheritance();
			analyzeVftables();
			return true;
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			log.appendException(e);
			return false;
		}
	}

	@Override
	public void analysisEnded(Program program) {
		manager = null;
		constructorAnalyzer = null;
		super.analysisEnded(program);
	}

	private void repairInheritance() throws CancelledException, InvalidDataTypeException {
		ClassTypeInfoManagerService service = getService();
		monitor.initialize(manager.getTypeCount());
		monitor.setMessage("Fixing Class Inheritance...");
		for (ClassTypeInfo type : manager.getTypes()) {
			monitor.checkCanceled();
			if (type.getName().contains(TypeInfoModel.STRUCTURE_NAME)) {
				// this works for both vs and gcc
				monitor.incrementProgress(1);
				continue;
			}
			if (useArchivedData) {
				String symbolName = TypeInfoUtils.getSymbolName(type);
				ArchivedClassTypeInfo data = service.getArchivedClassTypeInfo(symbolName);
				if (data != null) {
					((AbstractClassTypeInfoDB) type).setClassDataType(data.getClassDataType());
					monitor.incrementProgress(1);
					continue;
				}
			}
			// this takes care of everything
			try {
				type.getClassDataType();
			} catch (Exception e) {
				log.appendException(e);
			}
			monitor.incrementProgress(1);
		}
	}

	protected void analyzeVftables() throws Exception {
		ClassTypeInfoManagerService service = getService();
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Analyzing Vftables");
		for (Vtable vtable : manager.getVtables()) {
			monitor.checkCanceled();
			if (useArchivedData) {
				ArchivedVtable data =
					service.getArchivedVtable(VtableUtils.getSymbolName(vtable));
				if (data != null) {
					ApplyVtableDefinitionsBackgroundCmd cmd =
						new ApplyVtableDefinitionsBackgroundCmd(vtable, data);
					if (!cmd.applyTo(program, monitor)) {
						monitor.checkCanceled();
					}
					monitor.incrementProgress(1);
					continue;
				}
			}
			analyzeVftable(vtable.getTypeInfo());
			monitor.incrementProgress(1);
		}
		if (constructorAnalysisOption) {
			analyzeConstructors();
		}
	}

	protected boolean shouldAnalyzeConstructors() {
		return constructorAnalysisOption;
	}

	protected boolean shouldUseArchivedData() {
		return useArchivedData;
	}

	protected void analyzeConstructors() throws Exception {
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Creating Constructors");
		for (Vtable vtable : manager.getVtableIterable(true)) {
			monitor.checkCanceled();
			analyzeConstructor(vtable.getTypeInfo());
			monitor.incrementProgress(1);
		}
		clearCache();
	}

	protected static DecompilerAPI getDecompilerAPI(Program program) {
		return CppClassAnalyzerUtils.getService(program).getDecompilerAPI(program);
	}

	private void clearCache() {
		getDecompilerAPI(program).clearCache();
	}

	protected int getTimeout() {
		return decompilerTimeout;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_VTABLE_ANALYSIS_NAME, OPTION_DEFAULT_VTABLE_ANALYSIS, null,
			OPTION_VTABLE_ANALYSIS_DESCRIPTION);
		options.registerOption(OPTION_ARCHIVED_DATA_NAME, OPTION_DEFAULT_ARCHIVED_DATA, null,
			OPTION_ARCHIVED_DATA_DESCRIPTION);
		options.registerOption(OPTION_NAME_DECOMPILER_TIMEOUT_SECS,
			OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS, null,
			OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		constructorAnalysisOption =
			options.getBoolean(OPTION_VTABLE_ANALYSIS_NAME, OPTION_DEFAULT_VTABLE_ANALYSIS);
		useArchivedData =
			options.getBoolean(OPTION_ARCHIVED_DATA_NAME, OPTION_DEFAULT_ARCHIVED_DATA);
		decompilerTimeout =
			options.getInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS,
			OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS);
	}

	private ClassTypeInfoManagerService getService() {
		return CppClassAnalyzerUtils.getService(program);
	}

}
