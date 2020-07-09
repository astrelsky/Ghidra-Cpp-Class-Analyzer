package cppclassanalyzer.analysis.vs;

import java.util.HashSet;
import java.util.Set;

import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import cppclassanalyzer.analysis.cmd.AbstractDecompilerBasedConstructorAnalysisCmd;
import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import cppclassanalyzer.vs.VsClassTypeInfo;
import util.CollectionUtils;

public class VsDecompilerConstructorAnalysisCmd
		extends AbstractDecompilerBasedConstructorAnalysisCmd {


	private static final String NAME = VsDecompilerConstructorAnalysisCmd.class.getSimpleName();
	private static final String VECTOR_DESTRUCTOR = "vector_deleting_destructor";
	private static final String VBASE_DESTRUCTOR = "vbase_destructor";

	protected VsDecompilerConstructorAnalysisCmd(DecompilerAPI api) {
		super(NAME, api);
	}

	protected VsDecompilerConstructorAnalysisCmd(VsClassTypeInfo type, DecompilerAPI api) {
		super(NAME, api);
		this.type = type;
	}

	@Override
	protected boolean analyze() throws Exception {
		boolean result = super.analyze();
		if (result) {
			Vtable vtable = type.getVtable();
			GhidraClass gc = type.getGhidraClass();
			SymbolTable t = gc.getSymbol().getProgram().getSymbolTable();
			Iterable<Symbol> it = t.getChildren(gc.getSymbol());
			CollectionUtils.asStream(it)
				.filter(s -> s.getSymbolType() == SymbolType.FUNCTION)
				.filter(s -> s.getName().startsWith("~"))
				.map(Symbol::getObject)
				.map(Function.class::cast)
				.forEach(fun -> detectVirtualDestructors(fun, vtable));
		}
		return result;
	}

	private Set<Function> getThunks(Function function) {
		Set<Function> functions = new HashSet<>();
		functions.add(function);
		Address[] addresses = function.getFunctionThunkAddresses();
		if (addresses == null) {
			return functions;
		}
		for (Address address : addresses) {
			Function thunkFunction = fManager.getFunctionContaining(address);
			functions.add(thunkFunction);
		}
		return functions;
	}

	private void detectVirtualDestructors(Function destructor, Vtable vtable) {
			Function[][] fTable = vtable.getFunctionTables();
			if (fTable.length == 0) {
				return;
			}
			for (Function[] functionTable : vtable.getFunctionTables()) {
				if (functionTable.length == 0) {
					continue;
				}
				Set<Function> destructors = getThunks(destructor);
				Function vDestructor = CppClassAnalyzerUtils.createThunkFunctions(functionTable[0]);
				Function calledFunction = getFirstCalledFunction(vDestructor);
				if (calledFunction == null) {
					continue;
				}
				if (destructors.contains(calledFunction)) {
					try {
						ClassTypeInfoUtils.getClassFunction(
							program, type, vDestructor.getEntryPoint());
						vDestructor.setName(VECTOR_DESTRUCTOR, SourceType.IMPORTED);
						continue;
					} catch (Exception e) {
						Msg.error(this, "Failed to set "+VECTOR_DESTRUCTOR+" function.", e);
					}
				}
				Function vBaseDestructor = calledFunction;
				calledFunction = getFirstCalledFunction(calledFunction);
				if (calledFunction == null) {
					continue;
				}
				if (destructors.contains(calledFunction)) {
					try {
						ClassTypeInfoUtils.getClassFunction(
							program, type, vBaseDestructor.getEntryPoint());
						ClassTypeInfoUtils.getClassFunction(
							program, type, vDestructor.getEntryPoint());
						vBaseDestructor.setName(VBASE_DESTRUCTOR, SourceType.IMPORTED);
						vDestructor.setName(VECTOR_DESTRUCTOR, SourceType.IMPORTED);
						continue;
					} catch (Exception e) {
						Msg.error(this, "Failed to set "+VBASE_DESTRUCTOR+" function.", e);
					}
				}
			}
	}

	private Function getFirstCalledFunction(Function function) {
		if (function.getCalledFunctions(monitor).size() < 1) {
			return null;
		}
		Instruction inst = listing.getInstructionAt(function.getEntryPoint());
		AddressSetView body = function.getBody();
		while (inst.isFallthrough() && body.contains(inst.getAddress())) {
			inst = inst.getNext();
		}
		FlowType flow = inst.getFlowType();
		if (flow.isUnConditional() && !flow.isComputed()) {
			function = listing.getFunctionAt(inst.getFlows()[0]);
			if (function == null) {
				CreateFunctionCmd cmd = new CreateFunctionCmd(inst.getFlows()[0]);
				if (cmd.applyTo(program)) {
					function = cmd.getFunction();
				} else {
					return null;
				}
			}
			return CppClassAnalyzerUtils.createThunkFunctions(function);
		}
		return null;
	}

}
