//@category CppClassAnalyzer
import static ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory.getTypeInfo;

import java.util.LinkedList;
import java.util.List;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ClassReferences extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("This script is currently in development and may not function properly");
		SymbolTable table = currentProgram.getSymbolTable();
		List<Vtable> vftables = new LinkedList<>();
		List<Symbol> symbols = new LinkedList<>();
		table.getSymbols(TypeInfo.SYMBOL_NAME).forEach(symbols::add);
		monitor.initialize(symbols.size());
		monitor.setMessage("Locating Vtables");
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			TypeInfo ti = getTypeInfo(currentProgram, symbol.getAddress());
			try {
				ti.validate();
				if (ti instanceof ClassTypeInfo) {
					Vtable vtable = ((ClassTypeInfo) ti).getVtable();
					vtable.validate();
					vftables.add(vtable);
				}
			} catch (InvalidDataTypeException e) {}
			monitor.incrementProgress(1);
		}
		createClassReferences(vftables);
	}

	private void createClassReferences(List<Vtable> vftables) throws Exception {
		int count = 0;
		ReferenceManager manager = currentProgram.getReferenceManager();
		Listing listing = currentProgram.getListing();
		monitor.initialize(vftables.size());
		monitor.setMessage("Setting variable datatypes");
		for (Vtable vtable : vftables) {
			monitor.checkCanceled();
			Address vtableAddress = vtable.getTableAddresses()[0];
			VariableSetting:
			for (Reference ref : manager.getReferencesTo(vtableAddress)) {
				monitor.checkCanceled();
				if (manager.getReferencedVariable(ref) != null) {
					Variable var = manager.getReferencedVariable(ref);
					if (!(var.getDataType() instanceof Structure)) {
						var.setDataType(vtable.getTypeInfo().getClassDataType(),
										true, true, SourceType.ANALYSIS);
						count++;
						continue;
					}
				}
				Instruction inst = listing.getInstructionAt(ref.getFromAddress());
				if (inst == null) {
					continue;
				}
				Function function = listing.getFunctionContaining(inst.getAddress());
				if (function == null) {
					continue;
				}
				Object[] objects = inst.getInputObjects();
				if (!(objects[0] instanceof Register)) {
					continue;
				}
				Register register = (Register) objects[0];
				inst = inst.getNext();
				while (function.getBody().contains(inst.getAddress())) {
					monitor.checkCanceled();
					if (inst.getRegister(0) != null && inst.getRegister(0).contains(register)) {
						Reference[] refs = inst.getReferencesFrom();
						if (refs.length == 1 && !refs[0].isOffsetReference() && refs[0].isStackReference()) {
							Variable var = manager.getReferencedVariable(refs[0]);
							if (var != null) {
								var.setDataType(vtable.getTypeInfo().getClassDataType(),
												true, true, SourceType.ANALYSIS);
								count++;
								continue VariableSetting;
							}
						}
					}
					inst = inst.getNext();
				}
			}
			monitor.incrementProgress(1);
		}
		println("Created "+Integer.toString(count)+" class variabled references.");
	}
}
