package cppclassanalyzer.analysis.gcc;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.function.AddParameterCommand;
import ghidra.app.util.XReferenceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import cppclassanalyzer.analysis.cmd.AbstractConstructorAnalysisCmd;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public class GccConstructorAnalysisCmd extends AbstractConstructorAnalysisCmd {

	private static final String NAME = GccConstructorAnalysisCmd.class.getSimpleName();
	private static final String VTT_PARAM_NAME = "vttParam";

	private VttModel vtt = null;

	GccConstructorAnalysisCmd() {
		super(NAME);
	}

	public GccConstructorAnalysisCmd(VttModel vtt) {
		this();
		this.vtt = vtt;
		this.type = vtt.getVtableModel(0).getTypeInfo();
	}

	public GccConstructorAnalysisCmd(ClassTypeInfo typeinfo) {
		this();
		this.type = typeinfo;
	}

	@Override
	public void setTypeInfo(ClassTypeInfo typeinfo) {
		this.type = typeinfo;
		this.vtt = null;
	}

	public void setVtt(VttModel vtt) {
		this.vtt = vtt;
		this.type = vtt.getVtableModel(0).getTypeInfo();
	}

	private Address getCalledFunctionAddress(Address fromAddress) {
		Instruction instr = listing.getInstructionAt(fromAddress);
		while (!instr.getFlowType().isCall()) {
			if (monitor.isCancelled()) {
				return Address.NO_ADDRESS;
			}
			instr = instr.getNext();
		}
		return instr.getFlows()[0];
	}

	private boolean isInherited(ClassTypeInfo typeinfo, Namespace ns)
			throws InvalidDataTypeException {
		for (ClassTypeInfo parent : typeinfo.getParentModels()) {
			if (ns.equals(parent.getGhidraClass())) {
				return true;
			}
		}
		return false;
	}

	private void detectVirtualDestructors(Set<Address> addresses, Vtable vtable) throws Exception {
		Function[][] fTable = vtable.getFunctionTables();
		if (fTable.length == 0 || fTable[0].length == 0 || fTable[0][0] == null) {
			return;
		} else if (fTable[0][0].getName().equals(vtable.getTypeInfo().getName())) {
			// if this was marked as a constructor fix it
			fTable[0][0].removeTag(CppClassAnalyzerUtils.CONSTRUCTOR);
			createVirtualDestructors(vtable.getTypeInfo());
			return;
		}
		// The function must make a reference to the vtable
		for (Instruction inst : listing.getInstructions(fTable[0][0].getBody(), true)) {
			for (Reference ref : inst.getReferencesFrom()) {
				if (addresses.contains(ref.getToAddress())) {
					createVirtualDestructors(vtable.getTypeInfo());
					return;
				}
			}
		}
	}

	private void addAddresses(Set<Address> addresses, Collection<ClassTypeInfo> parents) {
		for (ClassTypeInfo parent : parents) {
			addAddresses(addresses, List.of(parent.getParentModels()));
			addAddresses(addresses, parent.getVirtualParents());
			Vtable parentVtable = parent.getVtable();
			if (parentVtable != Vtable.NO_VTABLE) {
				addresses.addAll(List.of(parentVtable.getTableAddresses()));
			}
		}
	}

	private boolean analyzeVtable(Vtable vtable) throws Exception {
		Address[] tableAddresses = vtable.getTableAddresses();
		if (tableAddresses.length == 0) {
			// no virtual functions, nothing to analyze.
			return true;
		}
		Data data = listing.getDataContaining(tableAddresses[0]);
		if (data == null) {
			return false;
		}
		ClassTypeInfo typeinfo = vtable.getTypeInfo();
		List<Reference> references = XReferenceUtils.getOffcutXReferences(data, -1);
		Collections.reverse(references);
		Set<Address> addresses = new HashSet<>(List.of(tableAddresses));
		addAddresses(addresses, List.of(typeinfo.getParentModels()));
		addAddresses(addresses, typeinfo.getVirtualParents());
		detectVirtualDestructors(addresses, vtable);
		for (Reference reference : references) {
			if (monitor.isCancelled()) {
				return false;
			}
			Address fromAddress = reference.getFromAddress();
			if (!fManager.isInFunction(fromAddress)) {
				continue;
			}
			if (isProcessed(fromAddress)) {
				Function function = fManager.getFunctionContaining(fromAddress);
				if (function != null && !function.getParentNamespace().isGlobal()) {
					Namespace ns = function.getParentNamespace();
					if (!(ns.equals(typeinfo.getGhidraClass()) || isInherited(typeinfo, ns))) {
						return true;
					}
					continue;
				}
			} else {
				try {
					if (reference.getReferenceType().equals(RefType.PARAM)) {
						Address calledAddress = getCalledFunctionAddress(fromAddress);
						if (!calledAddress.equals(Address.NO_ADDRESS)) {
							createConstructor(typeinfo, calledAddress, vtt != null);
						}
					} else if (reference.getReferenceType().isData()) {
						if (isValidConstructor(fromAddress, reference)) {
							createConstructor(typeinfo, fromAddress, false);
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
					Msg.trace(this, e);
				}
			}
		}
		return true;
	}

	private boolean isValidConstructor(Address address, Reference ref) {
		Function function = fManager.getFunctionContaining(address);
		Instruction inst = listing.getInstructionAt(function.getEntryPoint());
		while (function.getBody().contains(inst.getAddress())) {
			Reference[] references = inst.getReferencesFrom();
			if (references.length > 0) {
				for (Reference instRef : references) {
					if (instRef.getFromAddress().equals(inst.getAddress())) {
						return instRef.equals(ref);
					}
				}
			}
			if (inst.getFlowType().isFlow()) {
				for (int i = 0; i < inst.getDelaySlotDepth(); i++) {
					inst = inst.getNext();
					references = inst.getReferencesFrom();
					if (references.length > 0) {
						for (Reference instRef : references) {
							if (instRef.getFromAddress().equals(inst.getAddress())) {
								return instRef.equals(ref);
							}
						}
					}
				}
				return false;
			}
			inst = inst.getNext();
		}
		return false;
	}

	private boolean createFromVttModel() throws Exception {
		Address address = vtt.getAddress();
		Vtable vtable = vtt.getVtableModel(0);
		Function[][] fTables = vtable.getFunctionTables();
		if (fTables.length == 0 || fTables[0].length == 0 || fTables[0][0] == null) {
			return false;
		}
		for (int i = 0; i < vtt.getElementCount(); i++) {
			for (Reference reference : manager.getReferencesTo(address)) {
				if (isFunctionReference(reference)) {
					Function function = fManager.getFunctionContaining(reference.getFromAddress());
					if (fTables[0][0].equals(function)) {
						createVirtualDestructors(type);
					} else if (!CppClassAnalyzerUtils.isDestructor(function)) {
						createConstructor(type, function.getEntryPoint());
					}
				}
			}
			address = address.add(program.getDefaultPointerSize());
		}
		address = vtt.getAddress();
		for (int i = 0; i < vtt.getElementCount(); i++) {
			ClassTypeInfo baseType = vtt.getTypeInfo(i);
			if (!baseType.equals(type)) {
				for (Reference reference : manager.getReferencesTo(address)) {
					if (isFunctionReference(reference)) {
						if (reference.getReferenceType().equals(RefType.PARAM)) {
							Address fromAddress = reference.getFromAddress();
							Function caller = fManager.getFunctionContaining(fromAddress);
							if (caller == null || !caller.getParentNamespace().equals(
								type.getGhidraClass())) {
									continue;
							}
							Address calleeAddress = getCalledFunctionAddress(fromAddress);
							if (!calleeAddress.equals(Address.NO_ADDRESS)) {
								Function callee = ClassTypeInfoUtils.getClassFunction(
									program, baseType, calleeAddress);
								setFunction(
									baseType, callee, CppClassAnalyzerUtils.isDestructor(caller));
								setVttParam(callee, baseType);
							}
						}
					}
				}
			}
			address = address.add(program.getDefaultPointerSize());
		}
		return true;
	}

	private boolean isFunctionReference(Reference ref) {
		if (ref.isEntryPointReference()) {
			return false;
		}
		return program.getMemory().getBlock(ref.getFromAddress()).isExecute();
	}

	private void createConstructor(ClassTypeInfo typeinfo, Address address, boolean vttParam)
		throws Exception {
			Function function = createConstructor(typeinfo, address);
			createSubConstructors(typeinfo, function, false);
	}

	private void setVttParam(Function function, ClassTypeInfo typeinfo) {
		DataTypeManager dtm = program.getDataTypeManager();
		DataType vpp = dtm.getPointer(dtm.getPointer(VoidDataType.dataType));
		try {
			if (function.getParameterCount() == 1) {
				ParameterImpl param = new ParameterImpl(VTT_PARAM_NAME, vpp, program);
				AddParameterCommand cmd = new AddParameterCommand(function, param, 1, SourceType.ANALYSIS);
				cmd.applyTo(program);
			} else {
				Parameter param = function.getParameter(1);
				param.setName(VTT_PARAM_NAME, SourceType.IMPORTED);
				param.setDataType(vpp, SourceType.IMPORTED);
			}
		} catch (Exception e) {
			e.printStackTrace();
			Msg.trace(this, e);
		}
	}

	private void createVirtualDestructors(ClassTypeInfo typeinfo) throws Exception {
		Vtable vtable = typeinfo.getVtable();
		Function[][] functionTables = vtable.getFunctionTables();
		for (int i = 0; i < functionTables.length; i++) {
			for (int j = 0; j < functionTables[i].length && j < 2; j++) {
				Address address = functionTables[i][j].getEntryPoint();
				if (i == 0) {
					Function function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
					if (CppClassAnalyzerUtils.isDestructor(function)) {
						return;
					}
					setFunction(typeinfo, function, true);
				} else {
					functionTables[i][j].setThunkedFunction(functionTables[0][j]);
					try {
						functionTables[i][j].setParentNamespace(typeinfo.getGhidraClass());
					} catch (Exception e) {
						Msg.error(this, "Failed to set function namespace at "
										+ functionTables[i][j].getEntryPoint(), e);
					}
				}
			}
		}
	}

	@Override
	protected boolean analyze() throws Exception {
		try {
			return vtt != null ? createFromVttModel() : analyzeVtable(type.getVtable());
		} catch (InvalidDataTypeException e) {
			Msg.error(this, "analyze: "+type.getTypeName(), e);
			return false;
		}
	}
}
