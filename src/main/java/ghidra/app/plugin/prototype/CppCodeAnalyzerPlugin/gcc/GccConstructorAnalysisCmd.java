package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.function.AddParameterCommand;
import ghidra.app.util.XReferenceUtil;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class GccConstructorAnalysisCmd extends BackgroundCommand {

    private static final String NAME = GccConstructorAnalysisCmd.class.getSimpleName();
    private static final String VTT_PARAM_NAME = "vttParam";

    private VttModel vtt = null;
    private ClassTypeInfo type = null;
    private Program program;
    private TaskMonitor monitor;
    private FunctionManager fManager;
    private ReferenceManager manager;
    private Listing listing;

    private GccConstructorAnalysisCmd() {
        super(NAME, false, true, false);
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
            return vtt != null ? createFromVttModel() : analyzeVtable(type.getVtable());
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
            return false;
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

    private boolean isProcessed(Address address) {
        Function function = fManager.getFunctionContaining(address);
        return VftableAnalysisUtils.isProcessedFunction(function);
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

    private void detectVirtualDestructors(Data data, Vtable vtable)
        throws InvalidDataTypeException {
            Function[][] fTable = vtable.getFunctionTables();
            if (fTable[0][0] == null) {
                return;
            }
            List<Address> addresses = Arrays.asList(XReferenceUtil.getOffcutXRefList(data));
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
            if(!fManager.isInFunction(fromAddress)) {
                continue;
            }
            if (isProcessed(fromAddress)) {
                Function function = fManager.getFunctionContaining(fromAddress);
                if (function != null && !function.getParentNamespace().isGlobal()) {
                    Namespace ns = function.getParentNamespace();
                    if (!(ns.equals(typeinfo.getGhidraClass()) || isInherited(typeinfo, ns))) {
                        return true;
                    } continue;
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

    private boolean createFromVttModel() throws InvalidDataTypeException {
        Address address = vtt.getAddress();
        int pointerSize = program.getDefaultPointerSize();
        Vtable vtable = vtt.getVtableModel(0);
        analyzeVtable(vtable);
        for (int i = 0; i < vtt.getElementCount(); i++) {
            ClassTypeInfo baseType = vtt.getTypeInfo(i);
            if (baseType.equals(type)) {
                continue;
            }
            for (Reference reference : manager.getReferencesTo(address)) {
                if (reference.getReferenceType().equals(RefType.PARAM)) {
                    Address fromAddress = reference.getFromAddress();
                    Function caller = fManager.getFunctionContaining(fromAddress);
                    if (caller == null || !caller.getParentNamespace().equals(type.getGhidraClass())) {
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
            address = address.add(pointerSize);
        }
        return true;
    }

    private void createConstructor(ClassTypeInfo typeinfo, Address address, boolean vttParam)
        throws Exception {
            Function function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
            if (function == null) {
                Msg.info(this, "Null "+type.getName()+" Constructor at: "+address);
                return;
            }
            setFunction(typeinfo, function, false);
            if (vttParam) {
                setVttParam(function);
            } else {
                createSubConstructors(typeinfo, function, false);
            }
    }

    private void createSubConstructors(ClassTypeInfo typeinfo, Function constructor,
        boolean destructor) throws InvalidDataTypeException {
            ClassTypeInfo[] parents = typeinfo.getParentModels();
            Set<Function> calledFunctions = constructor.getCalledFunctions(monitor);
            if (parents.length == calledFunctions.size()) {
                Function[] functions =
                    calledFunctions.toArray(new Function[calledFunctions.size()]);
                for (int i = 0; i < parents.length; i++) {
                    ClassTypeInfoUtils.getClassFunction(
                        program, parents[i], functions[i].getEntryPoint());
                    setFunction(parents[i], functions[i], destructor);
                }
            }
    }

    private void setVttParam(Function function) {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType vpp = dtm.getPointer(dtm.getPointer(VoidDataType.dataType));
        try {
            if (function.getParameterCount() == 1) {
                ParameterImpl param = new ParameterImpl(VTT_PARAM_NAME, vpp, program);
                AddParameterCommand cmd = new AddParameterCommand(
                    function, param, 1, SourceType.ANALYSIS);
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

    private void setFunction(ClassTypeInfo typeinfo, Function function, boolean destructor) {
        try {
            String name = destructor ? "~"+typeinfo.getName() : typeinfo.getName();
            function.setName(name, SourceType.IMPORTED);
            function.setParentNamespace(typeinfo.getGhidraClass());
            VftableAnalysisUtils.setConstructorDestructorTag(program, function, destructor);
        } catch (Exception e) {
            Msg.error(this, e);
        }
    }

    private void createVirtualDestructors(ClassTypeInfo typeinfo)
        throws InvalidDataTypeException {
            Vtable vtable = typeinfo.getVtable();
            Function[][] functionTables = vtable.getFunctionTables();
            for (int i = 0; i < functionTables.length; i++) {
                for (int j = 0; j < functionTables[i].length && j < 2; j++) {
                    Address address = functionTables[i][j].getEntryPoint();
                    if (i == 0) {
                        Function function =
                            ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
                        setFunction(typeinfo, function, true);
                        if (j == 0) {
                            // Only do this for the [in-charge] destructor
                            createSubConstructors(typeinfo, function, true);
                        }
                    } else {
                        functionTables[i][j].setThunkedFunction(functionTables[0][j]);
                        try {
                            functionTables[i][j].setParentNamespace(typeinfo.getGhidraClass());
                        } catch (Exception e) {
                            Msg.error(this, "Failed to set function namespace at "
                                            +functionTables[i][j].getEntryPoint(), e);
                        }
                    }
                }
            }
    }
}
