package cppclassanalyzer.analysis.cmd;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import cppclassanalyzer.utils.ConstantPropagationUtils;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.datastruct.IntSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractConstructorAnalysisCmd extends BackgroundCommand {

	protected ClassTypeInfo type = null;
	protected Program program;
	protected TaskMonitor monitor;
	protected FunctionManager fManager;
	protected ReferenceManager manager;
	protected Listing listing;

	protected AbstractConstructorAnalysisCmd(String name) {
		super(name, false, true, false);
	}

	public AbstractConstructorAnalysisCmd(String name, ClassTypeInfo typeinfo) {
		this(name);
		this.type = typeinfo;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
		if (!(obj instanceof Program)) {
			String message = "Can only apply a constructor to a program.";
			Msg.error(this, message);
			return false;
		}
		this.program = (Program) obj;
		this.monitor = taskMonitor;
		this.listing = program.getListing();
		this.fManager = program.getFunctionManager();
		this.manager = program.getReferenceManager();
		try {
			// TODO follow calls to new to pick up simpler constructors first
			return analyze();
		} catch (CancelledException e) {
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			Msg.trace(this, e);
			return false;
		}
	}

	protected abstract boolean analyze() throws Exception;

	public void setTypeInfo(ClassTypeInfo typeinfo) {
		this.type = typeinfo;
	}

	protected boolean isProcessed(Address address) {
		Function function = fManager.getFunctionContaining(address);
		return !CppClassAnalyzerUtils.isDefaultFunction(function);
	}

	protected void setDestructor(ClassTypeInfo typeinfo, Function function) throws Exception {
		setFunction(typeinfo, function, true);
		if (function.isThunk()) {
			setFunction(typeinfo, function.getThunkedFunction(false), true);
		}
	}

	protected Function createConstructor(ClassTypeInfo typeinfo, Address address) throws Exception {
		Function function = fManager.getFunctionContaining(address);
		if (function != null && !CppClassAnalyzerUtils.isDefaultFunction(function)) {
			if (function.getName().equals(typeinfo.getName())) {
				return function;
			}
		} else if (function != null) {
			function = ClassTypeInfoUtils.getClassFunction(
				program, typeinfo, function.getEntryPoint());
		} else {
			function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
		}
		setFunction(typeinfo, function, false);
		createSubConstructors(typeinfo, function, false);
		return function;
	}

	protected boolean isConstructor(ClassTypeInfo typeinfo, Address address) {
		Function function = fManager.getFunctionContaining(address);
		if (function != null && function.getName().equals(typeinfo.getName())) {
			return true;
		}
		return false;
	}

	protected void setFunction(ClassTypeInfo typeinfo, Function function, boolean destructor)
			throws Exception {
		String name = destructor ? "~"+typeinfo.getName() : typeinfo.getName();
		function.setName(name, SourceType.IMPORTED);
		function.setParentNamespace(typeinfo.getGhidraClass());
		function.setCallingConvention(ClassTypeInfoUtils.THISCALL);
		CppClassAnalyzerUtils.setConstructorDestructorTag(function, !destructor);
	}

	protected void createSubConstructors(ClassTypeInfo type, Function constructor,
		boolean destructor) throws Exception {
			if (constructor.getParameter(0).isStackVariable()) {
				// TODO Need to figure out how to handle stack parameters
				return;
			}
			ConstructorAnalyzerHelper helper = new ConstructorAnalyzerHelper(type, constructor);
			SymbolicPropogator symProp = analyzeFunction(constructor);
			Register thisReg = getThisRegister(constructor.getParameter(0));
			for (Address address : helper.getCalledFunctionAddresses()) {
				monitor.checkCancelled();
				Instruction inst = listing.getInstructionAt(address);
				int delayDepth = inst.getDelaySlotDepth();
				if (delayDepth > 0) {
					while (inst.isInDelaySlot()) {
						monitor.checkCancelled();
						inst = inst.getNext();
					}
				}
				SymbolicPropogator.Value value =
					symProp.getRegisterValue(inst.getAddress(), thisReg);
				if (value == null || !helper.isValidOffset((int) value.getValue())) {
					continue;
				}
				ClassTypeInfo parent = helper.getParentAt((int) value.getValue());
				Function function = getCalledFunction(address);
				if (destructor) {
					setDestructor(parent, function);
				} else {
					createConstructor(parent, function.getEntryPoint());
				}
			}
	}

	private Function getCalledFunction(Address address) {
		Instruction inst = listing.getInstructionAt(address);

		// If it didn't this doesn't get reached
		Address target = inst.getReferencesFrom()[0].getToAddress();
		return listing.getFunctionAt(target);
	}

	private Register getThisRegister(Parameter param) {
		if (param.getAutoParameterType() == AutoParameterType.THIS) {
			return param.getRegister();
		}
		return null;
	}

	protected SymbolicPropogator analyzeFunction(Function function) throws CancelledException {
		return ConstantPropagationUtils.analyzeFunction(function, monitor);
	}

	protected static class ConstructorAnalyzerHelper {

		private final ClassTypeInfo type;
		private final Function function;
		private final IntSet offsets;

		protected ConstructorAnalyzerHelper(ClassTypeInfo type, Function function) {
			this.type = type;
			this.function = function;
			this.offsets = new IntSet(type.getParentModels().length);
			DataTypeComponent[] comps = type.getClassDataType().getDefinedComponents();
			Arrays.stream(comps)
				.filter(c -> c.getFieldName().contains("super_"))
				.mapToInt(DataTypeComponent::getOffset)
				.forEach(offsets::add);
		}

		protected List<Address> getCalledFunctionAddresses() {
			AddressSetView body = function.getBody();
			return function.getCalledFunctions(TaskMonitor.DUMMY)
				.stream()
				.filter(CppClassAnalyzerUtils::isDefaultFunction)
				.map(Function::getSymbol)
				.map(Symbol::getReferences)
				.flatMap(Arrays::stream)
				.map(Reference::getFromAddress)
				.filter(body::contains)
				.collect(Collectors.toList());
		}

		protected boolean isValidOffset(int offset) {
			return offsets.contains(offset);
		}

		protected ClassTypeInfo getParentAt(int offset) {
			if (!offsets.contains(offset)) {
				return null;
			}
			offsets.remove(offset);
			String name = type.getClassDataType()
				.getComponentAt(offset)
				.getFieldName()
				.replace("super_", "");
			return Arrays.stream(type.getParentModels())
				.filter(t -> t.getName().equals(name))
				.findFirst()
				.orElse(null);
		}
	}

}
