//@category CppClassAnalyzer
import java.util.LinkedList;
import java.util.List;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class ClassBuilder extends GhidraScript {

    private SymbolicPropogator symProp;

    private List<ClassTypeInfo> getClasses() {
        List<ClassTypeInfo> types = new LinkedList<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(TypeInfo.SYMBOL_NAME)) {
            TypeInfo type = TypeInfoFactory.getTypeInfo(currentProgram, symbol.getAddress());
            try {
                type.validate();
                if (type instanceof ClassTypeInfo) {
                    types.add((ClassTypeInfo) type);
                }
            } catch (InvalidDataTypeException e) {}
        }
        return types;
    }

    private void propagateConstants(Function function, ClassTypeInfo type) throws CancelledException {
        Parameter auto = function.getParameter(0);
        try {
            symProp.setRegister(type.getVtable().getTableAddresses()[0], auto.getRegister());
        } catch (InvalidDataTypeException e) {}
        ConstantPropagationContextEvaluator eval =
                new ConstantPropagationContextEvaluator(true);
        symProp.flowConstants(
            function.getEntryPoint(), function.getBody(), eval, true, monitor);
    }

    @Override
    public void run() throws Exception {
        symProp = new SymbolicPropogator(currentProgram);
        symProp.setParamRefCheck(true);
        symProp.setStoredRefCheck(true);
        List<ClassTypeInfo> types = getClasses();
        monitor.initialize(types.size());
        monitor.setMessage("Analyzing Destructors");
        for (ClassTypeInfo type : types) {
            monitor.checkCanceled();
            try {
                Vtable vtable = type.getVtable();
                Function[][] fTable = vtable.getFunctionTables();
                if (fTable.length > 0 && fTable[0].length > 0) {
                    Function destructor = fTable[0][0];
                    if (destructor != null && destructor.getName().startsWith("~")) {
                        analyzeDestructor(type, destructor);
                    }
                }
            } catch (InvalidDataTypeException e) {}
            monitor.incrementProgress(1);
        }
    }

    private Structure getMemberDataType(Function function) {
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(
            TypeInfo.SYMBOL_NAME, function.getParentNamespace())) {
                TypeInfo type = TypeInfoFactory.getTypeInfo(currentProgram, symbol.getAddress());
                try {
                    type.validate();
                    if (type instanceof ClassTypeInfo) {
                        return ((ClassTypeInfo) type).getClassDataType();
                    }
                } catch (InvalidDataTypeException e) {}
            }
        return null;
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

    private void analyzeDestructor(ClassTypeInfo type, Function destructor) throws Exception {
        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            destructor.getBody(), true);
        propagateConstants(destructor, type);
        Register thisRegister = destructor.getParameter(0).getRegister();
        for (Instruction inst : instructions) {
            monitor.checkCanceled();
            if (inst.getFlowType().isCall() && !inst.getFlowType().isComputed()) {
                Address[] flows = inst.getFlows();
                if (flows.length == 0) {
                    throw new Exception("Called function has no address? "+inst.getAddress().toString());
                }
                Function function = getFunctionAt(flows[0]);
                if (function == null || !function.getName().startsWith("~")) {
                    continue;
                }
                int delayDepth = inst.getDelaySlotDepth();
                for (int i = 0; i <= delayDepth; i++) {
                    inst = inst.getNext();
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
                    struct.insertAtOffset((int) value.getValue(), member, member.getLength());
                    println("Added member "+member.getName()+" to "+type.getName()+": "+inst.getAddress().toString());
                } else if (value != null && value.getValue() < 0) {
                    println("Virtual member access of "+type.getName()+" at "+inst.getAddress().toString());
                }
            }
        }
    }
}
