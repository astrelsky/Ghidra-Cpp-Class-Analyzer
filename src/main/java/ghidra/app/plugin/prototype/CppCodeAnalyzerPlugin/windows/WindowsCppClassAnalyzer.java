package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WindowsCppClassAnalyzer extends AbstractCppClassAnalyzer {

	private static final String NAME = "Windows C++ Class Analyzer";
	private static final String SYMBOL_NAME = "RTTI_Type_Descriptor";
	private static final String CLASS = "class";
	private static final String GUARD_FUNCTION = "_guard_check_icall";
	private static final String CFG_WARNING =
		"Control Flow Guard (CFG) detected. Vftables not analyzed.";

	private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();
	private WindowsVftableAnalysisCmd vfTableAnalyzer;
	private DecompilerAPI api;

	public WindowsCppClassAnalyzer() {
		super(NAME);
		setPriority(new RttiAnalyzer().getPriority().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (super.canAnalyze(program)) {
			return PEUtil.canAnalyze(program) && !GnuUtils.isGnuCompiler(program);
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (CppClassAnalyzerUtils.getManager(program) == null) {
			return false;
		}
		buildClassTypeInfoDatabase(program, monitor);
		return super.added(program, set, monitor, log);
	}

	private boolean hasGuardedVftables() {
		Iterable<Function> functions = program.getFunctionManager().getFunctions(true);
		return CollectionUtils.asStream(functions)
			.map(Function::getName)
			.anyMatch(GUARD_FUNCTION::equals);
	}

	@Override
	protected boolean hasVtt() {
		return false;
	}

	/**
	 * @deprecated use {@link ProgramClassTypeInfoManager#getTypes()}
	 * after invoking {@link #buildClassTypeInfoDatabase(Program, TaskMonitor)} or having run
	 * the WindowsCppClassAnalyzer.
	 *
	 * @param program the program
	 * @param monitor the monitor
	 * @return the typeinfo list
	 * @throws CancelledException if the operation is cancelled
	 */
	@Deprecated
	public static List<ClassTypeInfo> getClassTypeInfoList(Program program, TaskMonitor monitor)
			throws CancelledException {
		ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
		if (manager.getTypeCount() == 0) {
			buildClassTypeInfoDatabase(program, monitor);
		}
		return manager.getTypeStream().collect(Collectors.toList());
	}

	/**
	 * Locates known Run Time Type Information and adds them to the
	 * program's {@link ProgramClassTypeInfoManager}.
	 * @param program the program
	 * @param monitor the monitor
	 * @throws CancelledException if the operation is cancelled
	 */
	public static void buildClassTypeInfoDatabase(Program program, TaskMonitor monitor)
			throws CancelledException {
		ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
		DescriptorProcessor processor = new DescriptorProcessor(manager, monitor);
		SymbolTable table = program.getSymbolTable();
		AddressSet addrSet = new AddressSet();
		CppClassAnalyzerUtils.getAllDataBlocks(program)
			.forEach((b)->addrSet.addRange(b.getStart(), b.getEnd()));
		Iterable<Symbol> rawSymbols = table.getSymbols(addrSet, SymbolType.LABEL, true);
		List<Symbol> symbols = CollectionUtils.asStream(rawSymbols)
			 .filter((s)->s.getName().contains(SYMBOL_NAME))
			 .collect(Collectors.toList());
		monitor.initialize(symbols.size());
		monitor.setMessage("Locating Type Information");
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			TypeDescriptorModel descriptor = new TypeDescriptorModel(
				program, symbol.getAddress(), DEFAULT_OPTIONS);
			processor.process(descriptor);
			monitor.incrementProgress(1);
		}
	}

	@Override
	protected void analyzeVftables() throws Exception {
		if (!hasGuardedVftables()) {
			super.analyzeVftables();
		} else {
			if (shouldAnalyzeConstructors()) {
				analyzeConstructors();
			}
			log.appendMsg(CFG_WARNING);
		}
	}

	@Override
	protected boolean analyzeVftable(ClassTypeInfo type) {
		vfTableAnalyzer.setTypeInfo(type);
		return vfTableAnalyzer.applyTo(program);
	}

	@Override
	protected boolean analyzeConstructor(ClassTypeInfo type) {
	   constructorAnalyzer.setTypeInfo(type);
	   return constructorAnalyzer.applyTo(program);
	}

	@Override
	protected void init() {
		PluginTool tool = CppClassAnalyzerUtils.getTool(program);
		this.vfTableAnalyzer = new WindowsVftableAnalysisCmd();
		this.api = tool.getService(ClassTypeInfoManagerService.class).getDecompilerAPI(program);
		api.setMonitor(monitor);
		this.constructorAnalyzer = new VsDecompilerConstructorAnalysisCmd(api);
	}

	@Override
	protected boolean isDestructor(Function function) {
		return function.getName().contains("destructor");
	}

	private static final class DescriptorProcessor {

		private final ProgramClassTypeInfoManager manager;
		private final TaskMonitor monitor;

		DescriptorProcessor(ProgramClassTypeInfoManager manager, TaskMonitor monitor) {
			this.manager = manager;
			this.monitor = monitor;
		}

		void process(TypeDescriptorModel descriptor) throws CancelledException {
			try {
				if (!descriptor.getRefType().equals(CLASS)) {
					return;
				}
				descriptor.validate();
			} catch (InvalidDataTypeException | NullPointerException e) {
				return;
			}
			ClassTypeInfo type = RttiModelWrapper.getWrapper(descriptor);
			if (type.getNamespace() != null) {
				type = manager.resolve(type);
				Vtable vtable = type.findVtable(monitor);
				if (Vtable.isValid(vtable)) {
					manager.resolve(vtable);
				}
			}
		}
	}
}
