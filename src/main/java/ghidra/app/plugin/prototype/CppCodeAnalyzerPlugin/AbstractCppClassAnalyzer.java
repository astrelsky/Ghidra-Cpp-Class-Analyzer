package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import static ghidra.program.model.data.GenericCallingConvention.thiscall;

public abstract class AbstractCppClassAnalyzer extends AbstractAnalyzer {

	private static final String DESCRIPTION =
		"This analyzer analyzes RTTI metadata to recreate classes and their functions";

	private static final String OPTION_VTABLE_ANALYSIS_NAME = "Locate Constructors";
	private static final boolean OPTION_DEFAULT_VTABLE_ANALYSIS = false;
	private static final String OPTION_VTABLE_ANALYSIS_DESCRIPTION =
		"Turn on to search for Constructors/Destructors.";

	private static final String OPTION_FILLER_ANALYSIS_NAME = "Fill Class Fields";
	private static final boolean OPTION_DEFAULT_FILLER_ANALYSIS = false;
	private static final String OPTION_FILLER_ANALYSIS_DESCRIPTION =
		"Turn on to fill out the found class structures.";

	private boolean constructorAnalysisOption;
	private boolean fillClassFieldsOption;

	protected Program program;
	private TaskMonitor monitor;
	private SymbolicPropogator symProp;

	protected ProgramClassTypeInfoManager manager;

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
		return ClassTypeInfoManagerService.isEnabled(program);
	}

	protected abstract boolean hasVtt();
	protected abstract AbstractConstructorAnalysisCmd getConstructorAnalyzer();
	protected abstract boolean analyzeVftable(ClassTypeInfo type);
	protected abstract boolean analyzeConstructor(ClassTypeInfo type);
	protected abstract boolean isDestructor(Function function);

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		this.constructorAnalyzer = getConstructorAnalyzer();

		this.manager = ClassTypeInfoUtils.getManager(program);

		try {
			analyzeVftables();
			repairInheritance();
			if (fillClassFieldsOption) {
				fillStructures();
			}
			return true;
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			log.error("Ghidra-Cpp-Class-Analyzer", e.getMessage());
			return false;
		}
	}

	@Override
	public void analysisEnded(Program program) {
		manager = null;
		symProp = null;
		constructorAnalyzer = null;
		super.analysisEnded(program);
	}

	private static void ensureThisCall(Function fun) {
		PrototypeModel cc = fun.getCallingConvention();
		if (cc == null || !cc.getGenericCallingConvention().equals(thiscall)) {
			try {
				fun.setCallingConvention(thiscall.getDeclarationName());
				if (fun.getAutoParameterCount() < 1) {
					throw new AssertException(
						String.format("%s at %s was set to __thiscall but has no auto parameters",
									  fun.getName(true), fun.getEntryPoint()));
				}
			} catch (InvalidInputException e) {
				// cannot occur as an internal constant is being used
				throw new AssertException(e);
			}
		}
	}

	private void repairInheritance() throws CancelledException, InvalidDataTypeException {
		monitor.initialize(manager.getTypeCount());
		monitor.setMessage("Fixing Class Inheritance...");
		for (ClassTypeInfo type : manager.getTypes()) {
			monitor.checkCanceled();
			if (type.getName().contains(TypeInfoModel.STRUCTURE_NAME)) {
				// this works for both vs and gcc
				monitor.incrementProgress(1);
				continue;
			}
			// this takes care of everything
			type.getClassDataType();
			monitor.incrementProgress(1);
		}
	}

	private void fillStructures() throws Exception {
		if (fillClassFieldsOption) {
			symProp = new SymbolicPropogator(program);
			monitor.initialize(manager.getVtableCount());
			monitor.setMessage("Filling Class Structures...");
			for (Vtable vtable : manager.getVtables()) {
				monitor.checkCanceled();
				ClassTypeInfo type = vtable.getTypeInfo();
				if (type.getName().contains(TypeInfoModel.STRUCTURE_NAME)) {
					continue;
				}
				Function[][] fTable = vtable.getFunctionTables();
				if (fTable.length > 0 && fTable[0].length > 0) {
					Function destructor = fTable[0][0];
					if (destructor != null && isDestructor(destructor)) {
						// check that the function is __thiscall and set if necessary
						ensureThisCall(destructor);
						analyzeDestructor(type, destructor);
					}
				}
				monitor.incrementProgress(1);
			}
		}
	}

	private Structure getMemberDataType(Function function) {
		Parameter auto = function.getParameter(0);
		if (auto.getDataType() instanceof Pointer) {
			Pointer pointer = (Pointer) auto.getDataType();
			if (pointer.getDataType() instanceof Structure) {
				return (Structure) pointer.getDataType();
			}
		}
		return VariableUtilities.findExistingClassStruct(
			(GhidraClass) function.getParentNamespace(), program.getDataTypeManager());
	}

	private void clearComponent(Structure struct, int length, int offset) {
		if (offset >= struct.getLength()) {
			return;
		}
		for (int size = 0; size < length;) {
			DataTypeComponent comp = struct.getComponentAt(offset);
			if (comp!= null) {
				size += comp.getLength();
			} else {
				size++;
			}
			struct.deleteAtOffset(offset);
		}
	}

	private void propagateConstants(Function function, ClassTypeInfo type)
		throws CancelledException {
			Parameter auto = function.getParameter(0);
			if (auto != null && !auto.isStackVariable()) {
				final Vtable vtable = type.getVtable();
				if (Vtable.isValid(vtable)) {
					symProp.setRegister(vtable.getTableAddresses()[0], auto.getRegister());
					ConstantPropagationContextEvaluator eval =
							new ConstantPropagationContextEvaluator(true);
					symProp.flowConstants(
						function.getEntryPoint(), function.getBody(), eval, false, monitor);
				}
			}
			// TODO await stack variable support in SymbolicPropogator
	}

	private void analyzeDestructor(ClassTypeInfo type, Function destructor) throws Exception {
		// if the return type is undefined fix it and set it to void
		if (Undefined.isUndefined(destructor.getReturnType())) {
			destructor.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
		}
		InstructionIterator instructions = program.getListing().getInstructions(
			destructor.getBody(), true);
		propagateConstants(destructor, type);
		Register thisRegister = destructor.getParameter(0).getRegister();
		for (Instruction inst : instructions) {
			monitor.checkCanceled();
			if (inst.getFlowType().isCall() && !inst.getFlowType().isComputed()) {
				Function function = getFunction(inst.getFlows()[0]);
				if (function == null || !isDestructor(function)) {
					continue;
				}
				int delayDepth = inst.getDelaySlotDepth();
				if (delayDepth > 0) {
						for (int i = 0; i <= delayDepth; i++) {
							inst = inst.getNext();
						}
					}
				SymbolicPropogator.Value value = symProp.getRegisterValue(
					inst.getAddress(), thisRegister);
				if (value != null && value.getValue() > 0) {
					Structure struct = type.getClassDataType();
					DataTypeComponent comp = struct.getComponentAt((int) value.getValue());
					Structure member = getMemberDataType(function);
					if (comp != null) {
						if (comp.getDataType() instanceof Structure) {
							continue;
						}
						clearComponent(struct, member.getLength(), (int) value.getValue());
					}
					struct.insertAtOffset((int) value.getValue(), member, member.getLength(), member.getName(), null);
					struct.getDataTypeManager().resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
				}
			}
		}
	}

	private Function getFunction(Address address) {
		Listing listing = program.getListing();
		if (listing.getInstructionAt(address) == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			if (!cmd.applyTo(program)) {
				return null;
			}
		}
		FunctionManager manager = program.getFunctionManager();
		Function function = manager.getFunctionContaining(address);
		if (function == null) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(address, true);
			if (cmd.applyTo(program)) {
				return cmd.getFunction();
			}
		}
		return function;
	}

	protected void analyzeVftables() throws Exception {
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Analyzing Vftables");
		for (Vtable vtable : manager.getVtables()) {
			monitor.checkCanceled();
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

	protected void analyzeConstructors() throws Exception {
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Creating Constructors");
		for (Vtable vtable : manager.getVtableIterable(true)) {
			monitor.checkCanceled();
			analyzeConstructor(vtable.getTypeInfo());
			monitor.incrementProgress(1);
		}
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		options.registerOption(OPTION_VTABLE_ANALYSIS_NAME, OPTION_DEFAULT_VTABLE_ANALYSIS, null,
			OPTION_VTABLE_ANALYSIS_DESCRIPTION);
		options.registerOption(OPTION_FILLER_ANALYSIS_NAME, OPTION_DEFAULT_FILLER_ANALYSIS, null,
			OPTION_FILLER_ANALYSIS_DESCRIPTION);

		constructorAnalysisOption =
			options.getBoolean(OPTION_VTABLE_ANALYSIS_NAME, OPTION_DEFAULT_VTABLE_ANALYSIS);
		fillClassFieldsOption =
			options.getBoolean(OPTION_FILLER_ANALYSIS_NAME, OPTION_DEFAULT_FILLER_ANALYSIS);
	}

}
