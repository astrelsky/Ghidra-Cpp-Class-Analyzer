package cppclassanalyzer.analysis.vs;

import java.util.*;
import java.util.stream.Collectors;

import cppclassanalyzer.analysis.AbstractCppClassAnalyzer;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import cppclassanalyzer.vs.RttiModelWrapper;
import cppclassanalyzer.vs.VsClassTypeInfo;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class VsCppClassAnalyzer extends AbstractCppClassAnalyzer {

	private static final String NAME = "Windows C++ Class Analyzer";
	private static final String SYMBOL_NAME = "RTTI_Type_Descriptor";

	// union doesn't really do much good but it isn't included for completion
	private static final Set<String> REF_TYPES = Set.of("class", "struct", "union");
	private static final String GUARD_FUNCTION = "_guard_check_icall";
	private static final String CFG_WARNING =
		"Control Flow Guard (CFG) detected. Vftables not analyzed.";

	private static final DataApplyOptions DEFAULT_APPLY_OPTIONS = new DataApplyOptions();

	static {
		DEFAULT_APPLY_OPTIONS.setClearInstructions(true);
		DEFAULT_APPLY_OPTIONS.setFollowData(false);
	}

	private VsVftableAnalysisCmd vfTableAnalyzer;
	private DecompilerAPI api;

	public VsCppClassAnalyzer() {
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
				program, symbol.getAddress(), VsClassTypeInfo.DEFAULT_OPTIONS);
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
		this.vfTableAnalyzer = new VsVftableAnalysisCmd();
		this.api = getDecompilerAPI(program);
		api.setMonitor(monitor);
		api.setTimeout(getTimeout());
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
			this.monitor = new CancelOnlyWrappingTaskMonitor(monitor);
		}

		void process(TypeDescriptorModel descriptor) throws CancelledException {
			try {
				if (!REF_TYPES.contains(descriptor.getRefType())) {
					return;
				}
				descriptor.validate();
			} catch (InvalidDataTypeException | NullPointerException e) {
				return;
			}
			VsClassTypeInfo type = (VsClassTypeInfo) manager.getType(descriptor.getAddress());
			if (type == null) {
				type = RttiModelWrapper.getWrapper(descriptor, monitor);
			}
			if (type != null) {
				fixMissingMarkup(type);
				type = (VsClassTypeInfo) manager.resolve(type);
				Vtable vtable = type.findVtable(monitor);
				if (Vtable.isValid(vtable)) {
					manager.resolve(vtable);
				}
			} else {
				String msg = String.format(
					"Unable to process %s at %s due to lack of information",
					descriptor.getDescriptorAsNamespace().getName(true), descriptor.getAddress());
				Msg.info(this, msg);
			}
		}

		private void fixMissingMarkup(VsClassTypeInfo type) throws CancelledException {
			// Only create the slow Rtti#Models if necessary
			if (needsRtti3Markup(type)) {
				markupRtti3(type);
			}
			if (needsRtti2Markup(type)) {
				markupRtti2(type);
			}
		}

		private boolean needsRtti3Markup(VsClassTypeInfo type) {
			return needsRttiMarkup(type, VsClassTypeInfo.HIERARCHY_SYMBOL_NAME);
		}

		private boolean needsRtti2Markup(VsClassTypeInfo type) {
			return needsRttiMarkup(type, VsClassTypeInfo.BASE_ARRAY_SYMBOL_NAME);
		}

		private boolean needsRttiMarkup(VsClassTypeInfo type, String symbolName) {
			GhidraClass gc = type.getGhidraClass();
			Program program = gc.getSymbol().getProgram();
			SymbolIterator it = program.getSymbolTable().getChildren(gc.getSymbol());
			return CollectionUtils.asStream(it)
				.map(Symbol::getName)
				.noneMatch(s -> s.contains(symbolName));
		}

		private void markupRtti3(VsClassTypeInfo type) {
			Rtti3Model rtti3 = type.getHierarchyDescriptor();
			if (rtti3 == null) {
				return;
			}
			CreateRtti3BackgroundCmd cmd =
				new CreateRtti3BackgroundCmd(
					rtti3.getAddress(), VsClassTypeInfo.DEFAULT_OPTIONS,
					DEFAULT_APPLY_OPTIONS);
			cmd.applyTo(rtti3.getProgram());
		}

		private void markupRtti2(VsClassTypeInfo type) {
			Rtti2Model rtti2 = type.getBaseClassArray();
			if (rtti2 == null) {
				return;
			}
			CreateRtti2BackgroundCmd cmd =
				new CreateRtti2BackgroundCmd(
					rtti2.getAddress(), rtti2.getCount(),
					VsClassTypeInfo.DEFAULT_OPTIONS, DEFAULT_APPLY_OPTIONS);
			cmd.applyTo(rtti2.getProgram());
		}
	}
}
