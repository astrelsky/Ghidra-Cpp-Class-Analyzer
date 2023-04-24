package cppclassanalyzer.analysis.vs;

import java.util.*;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.XReferenceUtils;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import cppclassanalyzer.analysis.cmd.AbstractConstructorAnalysisCmd;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public class VsConstructorAnalysisCmd extends AbstractConstructorAnalysisCmd {

	private static final String NAME = VsConstructorAnalysisCmd.class.getSimpleName();
	private static final String VECTOR_DESTRUCTOR = "vector_deleting_destructor";
	private static final String VBASE_DESTRUCTOR = "vbase_destructor";

	VsConstructorAnalysisCmd() {
		super(NAME);
	}

	public VsConstructorAnalysisCmd(ClassTypeInfo typeinfo) {
		super(NAME, typeinfo);
	}

	private boolean isDebugable() {
		PdbProgramAttributes pdb = new PdbProgramAttributes(program);
		return pdb.getPdbFile() != null;
	}

	private Address getFunctionStart(Address address) {
		Instruction inst = listing.getInstructionAt(address);
		while (inst.getFallFrom() != null) {
			inst = inst.getPrevious();
		}
		return inst.getAddress();
	}

	private boolean analyzeVtable(Vtable vtable) throws Exception,
		InvalidDataTypeException {
			Address[] tableAddresses = vtable.getTableAddresses();
			if (tableAddresses.length == 0) {
				// no virtual functions, nothing to analyze.
				return true;
			}
			Address tableAddress = tableAddresses[0];
			monitor.checkCancelled();
			Data data = listing.getDataContaining(tableAddress);
			if (data == null) {
				return false;
			}
			ClassTypeInfo typeinfo = vtable.getTypeInfo();

			List<Reference> references = XReferenceUtils.getXReferences(data, -1);
			if (references.isEmpty()) {
				return false;
			}
			Set<Function> functions = new LinkedHashSet<>(references.size());
			if (!isDebugable()) {
				Function function = fManager.getFunctionContaining(references.get(0).getFromAddress());
				if (function == null) {
					data = listing.getDataAt(references.get(0).getFromAddress());
					if (data != null && data.isPointer()) {
						references = XReferenceUtils.getXReferences(data, -1);
						Collections.reverse(references);
						Address start = getFunctionStart(references.get(0).getFromAddress());
						CreateFunctionCmd cmd = new CreateFunctionCmd(start, true);
						if (cmd.applyTo(program)) {
							function = cmd.getFunction();
						} else {
							return false;
						}
					}
				}
				createConstructor(typeinfo, function.getEntryPoint());
				setDestructor(typeinfo, function);
				return true;
			}
			Collections.reverse(references);
			for (Reference ref : references) {
				monitor.checkCancelled();
				Address fromAddress = ref.getFromAddress();
				if(!fManager.isInFunction(fromAddress)) {
					continue;
				}
				Function function = fManager.getFunctionContaining(fromAddress);
				createConstructor(typeinfo, function.getEntryPoint());
				functions.add(function);
			}
			if (functions.size() < 2) {
				return false;
			}
			Iterator<Function> iter =functions.iterator();
			Function destructor = iter.next();
			setDestructor(typeinfo, destructor);
			detectVirtualDestructors(destructor, vtable);
			createSubConstructors(typeinfo, iter.next(), false);
			return true;
	}

	private Set<Function> getThunks(Function function) {
		Set<Function> functions = new HashSet<>();
		functions.add(function);
		Address[] addresses = function.getFunctionThunkAddresses(false);
		if (addresses == null) {
			return functions;
		}
		for (Address address : addresses) {
			Function thunkFunction = fManager.getFunctionContaining(address);
			functions.add(thunkFunction);
		}
		return functions;
	}

	private void detectVirtualDestructors(Function destructor, Vtable vtable)
		throws InvalidDataTypeException {
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
		final FlowType flow = inst.getFlowType();
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

	@Override
	protected boolean analyze() throws Exception {
		return analyzeVtable(type.getVtable());
	}

}
