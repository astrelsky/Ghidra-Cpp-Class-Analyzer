package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vftable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils;
import ghidra.app.util.XReferenceUtil;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WindowsConstructorAnalysisCmd extends BackgroundCommand {

    private static final String NAME = WindowsConstructorAnalysisCmd.class.getSimpleName();
    private static final String VECTOR_DESTRUCTOR = "vector_deleting_destructor";
    private static final String VBASE_DESTRUCTOR = "vbase_destructor";

    private ClassTypeInfo type = null;
    private Program program;
    private TaskMonitor monitor;
    private FunctionManager fManager;
    private Listing listing;

    private WindowsConstructorAnalysisCmd() {
        super(NAME, false, true, false);
    }

    public WindowsConstructorAnalysisCmd(ClassTypeInfo typeinfo) {
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
        try {
            return analyzeVtable(type.getVtable());
        } catch (CancelledException e) {
            return false;
        }
    }

    private void setDestructor(ClassTypeInfo typeinfo, Function function) {
        setFunction(typeinfo, function, true);
        if (function.isThunk()) {
            setFunction(typeinfo, function.getThunkedFunction(false), true);
        }
    }

    private Set<Function> getThunks(Function function) {
        FunctionManager manager = program.getFunctionManager();
        Set<Function> functions = new HashSet<>();
        functions.add(function);
        for (Address address : function.getFunctionThunkAddresses()) {
            functions.add(manager.getFunctionContaining(address));
        }
        return functions;
    }

    private void detectVirtualDestructors(Function destructor, Vftable vtable) {
        Function[][] fTable = vtable.getFunctionTables();
        if (fTable.length == 0) {
            return;
        }
        for (Function[] functionTable : vtable.getFunctionTables()) {
            if (functionTable.length == 0) {
                continue;
            }
            Set<Function> destructors = getThunks(destructor);
            Function vDestructor = VftableAnalysisUtils.recurseThunkFunctions(
                program, functionTable[0].getThunkedFunction(true));
            Function calledFunction = getFirstCalledFunction(vDestructor);
            if (calledFunction == null) {
                continue;
            }
            if (destructors.contains(calledFunction)) {
                try {
                    ClassTypeInfoUtils.getClassFunction(program, type, vDestructor.getEntryPoint());
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
                    ClassTypeInfoUtils.getClassFunction(program, type, vBaseDestructor.getEntryPoint());
                    ClassTypeInfoUtils.getClassFunction(program, type, vDestructor.getEntryPoint());
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
        if (inst.getFlowType().isUnConditional()) {
            function = listing.getFunctionAt(inst.getFlows()[0]);
            if (function == null) {
                CreateFunctionCmd cmd = new CreateFunctionCmd(inst.getFlows()[0]);
                if (cmd.applyTo(program)) {
                    function = cmd.getFunction();
                } else {
                    return null;
                }
            }
            return VftableAnalysisUtils.recurseThunkFunctions(
                program, function);
        }
        return null;
    }

    private boolean analyzeVtable(Vftable vtable) throws CancelledException {
        if (vtable == null || !vtable.isValid()) {
            Msg.info(this, type.getName()+" vtable invalid or null");
            return false;
        }
        Address[] tableAddresses = vtable.getTableAddresses();
        if (tableAddresses.length == 0) {
            // no virtual functions, nothing to analyze.
            return true;
        }
        for (Address tableAddress : tableAddresses) {
            monitor.checkCanceled();
            Data data = listing.getDataContaining(tableAddress);
            if (data == null) {
                continue;
            }
            ClassTypeInfo typeinfo = vtable.getTypeInfo();
            
            List<Address> references = Arrays.asList(XReferenceUtil.getXRefList(data, -1));
            if (references.isEmpty()) {
                continue;
            }
            Set<Function> functions = new LinkedHashSet<>(references.size());
            Collections.reverse(references);
            for (Address fromAddress : references) {
                monitor.checkCanceled();
                if(!fManager.isInFunction(fromAddress)) {
                    continue;
                }
                Function function = fManager.getFunctionContaining(fromAddress);
                createConstructor(typeinfo, function.getEntryPoint());
                functions.add(function);
            }
            Function destructor = functions.iterator().next();
            setDestructor(typeinfo, destructor);
            detectVirtualDestructors(destructor, vtable);
        }
        return true;
    }

    private void createConstructor(ClassTypeInfo typeinfo, Address address) {
        Function function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
        if (function == null) {
            Msg.info(this, "Null "+type.getName()+" Constructor at: "+address);
            return;
        }
        setFunction(typeinfo, function, false);
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

}
