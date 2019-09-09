package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.function.AddParameterCommand;
import ghidra.app.util.XReferenceUtil;
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
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

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
        try {
            this.type = vtt.getVtableModel(0).getTypeInfo();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
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
        try {
            this.type = vtt.getVtableModel(0).getTypeInfo();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
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

    private boolean isInherited(ClassTypeInfo typeinfo, Namespace ns) throws InvalidDataTypeException {
        for (ClassTypeInfo parent : typeinfo.getParentModels()) {
            if (ns.equals(parent.getGhidraClass())) {
                return true;
            }
        }
        return false;
    }

    private void detectVirtualDestructors(Data data, Vtable vtable) throws InvalidDataTypeException {
        Function[][] fTable = vtable.getFunctionTables();
        if (fTable.length == 0 || fTable[0].length == 0 || fTable[0][0] == null) {
            return;
        } else if (fTable[0][0].getName().equals(vtable.getTypeInfo().getName())) {
            createVirtualDestructors(vtable.getTypeInfo());
            return;
        }
        List<Address> addresses = Arrays.asList(XReferenceUtil.getXRefList(data));
        Set<Function> functions = new HashSet<>(addresses.size());
        addresses.forEach((a) -> functions.add(fManager.getFunctionContaining(a)));
        if (functions.contains(fTable[0][0])) {
            createVirtualDestructors(vtable.getTypeInfo());
        }
    }

    private boolean analyzeVtable(Vtable vtable) throws InvalidDataTypeException {
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
        List<Reference> references = Arrays.asList(XReferenceUtil.getOffcutXReferences(data, -1));
        Collections.reverse(references);
        detectVirtualDestructors(data, vtable);
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
                        createConstructor(typeinfo, fromAddress, false);
                    }
                } catch (Exception e) {
                    Msg.error(this, e);
                }
            }
        }
        return true;
    }

    private boolean createFromVttModel() throws Exception {
        Memory mem = program.getMemory();
        Address address = vtt.getAddress();
        Vtable vtable = vtt.getVtableModel(0);
        Data data = program.getListing().getDataAt(address);
        analyzeVtable(vtable);
        if (data != null) {
            for (Address reference : XReferenceUtil.getOffcutXRefList(data)) {
                if (mem.getBlock(reference).isExecute() && !isConstructor(type, reference)) {
                    createConstructor(vtable.getTypeInfo(), reference, true);
                }
            }
            for (Address reference : XReferenceUtil.getXRefList(data)) {
                if (mem.getBlock(reference).isExecute() && !isConstructor(type, reference)) {
                    createConstructor(vtable.getTypeInfo(), reference, true);
                }
            }
            detectVirtualDestructors(data, vtable);
        }
        for (int i = 0; i < vtt.getElementCount(); i++) {
            ClassTypeInfo baseType = vtt.getTypeInfo(i);
            if (!baseType.equals(type)) {
                for (Reference reference : manager.getReferencesTo(address)) {
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
                                baseType, callee, VftableAnalysisUtils.isDestructor(caller));
                            setVttParam(callee);
                        }
                    }
                }
            }
            address = address.add(program.getDefaultPointerSize());
        }
        return true;
    }

    private void createConstructor(ClassTypeInfo typeinfo, Address address, boolean vttParam)
        throws Exception {
            Function function = createConstructor(typeinfo, address);
            createSubConstructors(typeinfo, function, false);
    }

    private void setVttParam(Function function) {
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
            Msg.error(this, e);
        }
    }

    private void createVirtualDestructors(ClassTypeInfo typeinfo) throws InvalidDataTypeException {
        Vtable vtable = typeinfo.getVtable();
        Function[][] functionTables = vtable.getFunctionTables();
        for (int i = 0; i < functionTables.length; i++) {
            for (int j = 0; j < functionTables[i].length && j < 2; j++) {
                Address address = functionTables[i][j].getEntryPoint();
                if (i == 0) {
                    Function function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
                    if (VftableAnalysisUtils.isDestructor(function)) {
                        return;
                    }
                    setFunction(typeinfo, function, true);
                } else {
                    functionTables[i][j].setThunkedFunction(functionTables[0][j]);
                    try {
                        functionTables[i][j].setParentNamespace(typeinfo.getGhidraClass());
                    } catch (Exception e) {
                        Msg.error(this, "Failed to set function namespace at " + functionTables[i][j].getEntryPoint(),
                                e);
                    }
                }
            }
        }
    }

    @Override
    protected boolean analyze() throws Exception {
        return vtt != null ? createFromVttModel() : analyzeVtable(type.getVtable());
    }
}
