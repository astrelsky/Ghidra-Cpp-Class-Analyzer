//@category CppClassAnalyzer
import java.util.List;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
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
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;

public class DynamicCaster extends GhidraScript {

    private SymbolicPropogator symProp;
    private Parameter srcPointer;
    private Parameter srcType;

    @Override
    public void run() throws Exception {
        println("This script is currently in development and may not function properly");
        List<Function> functions = getGlobalFunctions("__dynamic_cast");
        if (functions.size() > 1) {
            println("More than one __dynamic_cast function found.");
            return;
        }
        if (functions.isEmpty()) {
            println("__dynamic_cast function not found");
            return;
        }
        Function dynamicCast = functions.get(0);
        Parameter[] parameters = dynamicCast.getParameters();
        if (parameters.length != 4) {
            println("Unexpected number of __dynamic_cast parameters");
            return;
        }
        srcPointer = parameters[0];
        srcType = parameters[1];
        symProp = new SymbolicPropogator(currentProgram);
        symProp.setParamRefCheck(true);
        symProp.setReturnRefCheck(true);
        symProp.setStoredRefCheck(true);
        Reference[] references = getReferencesTo(dynamicCast.getEntryPoint());
        monitor.initialize(references.length);
        monitor.setMessage("Analyzing __dynamic_cast calls");
        for (Reference reference : references) {
            monitor.checkCanceled();
            if (!reference.getReferenceType().isFlow()) {
                monitor.incrementProgress(1);
                continue;
            }
            ConstantPropagationContextEvaluator eval =
                new ConstantPropagationContextEvaluator(true);
            Function function = getFunctionContaining(reference.getFromAddress());
            Instruction inst = getInstructionAt(reference.getFromAddress());
            int delaySlotDepth = inst.getDelaySlotDepth();
            for (int i = 0; i < delaySlotDepth; i++) {
                inst = inst.getNext();
            }
            symProp.flowConstants(
                function.getEntryPoint(), function.getBody(), eval, true, monitor);
            doDynamicCast(reference.getFromAddress());
            monitor.incrementProgress(1);
        }
    }

    private void doDynamicCast(Address address) throws Exception {
        SymbolicPropogator.Value srcValue = symProp.getRegisterValue(
            address, srcPointer.getRegister());
        SymbolicPropogator.Value srcTypeValue = symProp.getRegisterValue(
            address, srcType.getRegister());
        Address dataAddress = null;
        Function function = getFunctionContaining(address);
        if (srcValue == null) {
            AddressRange range = new AddressRangeImpl(function.getEntryPoint(), address);
            Instruction inst = getInstructionAt(function.getEntryPoint());
            while (range.contains(inst.getAddress())) {
                for (Reference reference : inst.getReferencesFrom()) {
                    if (reference.getReferenceType().isData()) {
                        for (Object object : inst.getResultObjects()) {
                            if (object instanceof Register) {
                                Register reg = ((Register) object).getBaseRegister();
                                if (reg.contains(srcPointer.getRegister())) {
                                    dataAddress = reference.getToAddress();
                                    break;
                                }
                            }
                        }
                    }
                }
                inst = inst.getNext();
            }
        } else {
            dataAddress = toAddr(srcValue.getValue());
        }
        if (dataAddress != null && srcTypeValue != null) {
            Address typeAddress = toAddr(srcTypeValue.getValue());
            if (TypeInfoUtils.isTypeInfo(currentProgram, typeAddress)) {
                ClassTypeInfo type = (ClassTypeInfo) TypeInfoFactory.getTypeInfo(
                    currentProgram, typeAddress);
                DataTypeManager dtm = currentProgram.getDataTypeManager();
                DataType dt = srcValue == null ? dtm.getPointer(type.getClassDataType())
                    : type.getClassDataType();
                if (isValidDataAddress(dataAddress)) {
                    Data data = getDataAt(dataAddress);
                    if (data == null || Undefined.isUndefined(data.getDataType())) {
                        println("created "+dt.toString()+" at "+dataAddress.toString()+" from "+address.toString());
                        doCreateData(dataAddress, dt);
                    }
                }
            }
        }
    }

    private boolean isValidDataAddress(Address address) {
        return GnuUtils.isDataBlock(getMemoryBlock(address));
    }

    private Data doCreateData(Address address, DataType dt) throws Exception {
        return DataUtilities.createData(currentProgram, address, dt,
                                 currentProgram.getDefaultPointerSize(), false,
                                 ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
    }
}
