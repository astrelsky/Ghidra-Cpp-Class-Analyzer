package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsConstructorAnalysisCmd;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
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
        return VftableAnalysisUtils.isProcessedFunction(function);
    }

    protected void setDestructor(ClassTypeInfo typeinfo, Function function) {
        setFunction(typeinfo, function, true);
        if (function.isThunk()) {
            setFunction(typeinfo, function.getThunkedFunction(false), true);
        }
    }

    protected Function createConstructor(ClassTypeInfo typeinfo, Address address) {
        Function function = fManager.getFunctionContaining(address);
        if (function != null && VftableAnalysisUtils.isProcessedFunction(function)) {
            try {
                if (function.getName().equals(typeinfo.getName())) {
                    return function;
                }
            } catch (InvalidDataTypeException e) {
                Msg.error(this, "createConstructor", e);
            }
        } else if (function != null) {
            function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, function.getEntryPoint());
        } else {
            function = ClassTypeInfoUtils.getClassFunction(program, typeinfo, address);
        }
        setFunction(typeinfo, function, false);
        return function;
    }

    protected boolean isConstructor(ClassTypeInfo typeinfo, Address address) {
        Function function = fManager.getFunctionContaining(address);
        try {
            if (function != null && function.getName().equals(typeinfo.getName())) {
                return true;
            }
        } catch (InvalidDataTypeException e) {
            Msg.error(this, "isConstructor", e);
        }
        return false;
    }

    protected void setFunction(ClassTypeInfo typeinfo, Function function, boolean destructor) {
        try {
            String name = destructor ? "~"+typeinfo.getName() : typeinfo.getName();
            function.setName(name, SourceType.IMPORTED);
            function.setParentNamespace(typeinfo.getGhidraClass());
            VftableAnalysisUtils.setConstructorDestructorTag(program, function, destructor);
        } catch (Exception e) {
            Msg.error(this, "setFunction", e);
        }
    }

    protected void createSubConstructors(ClassTypeInfo typeinfo, Function constructor, boolean destructor)
            throws Exception {
                Set<ClassTypeInfo> parents =
                    new LinkedHashSet<>(typeinfo.getVirtualParents());
                parents.addAll(Arrays.asList(typeinfo.getParentModels()));
                List<Function> functions = getCalledFunctions(constructor);
                if (functions.size() < parents.size()) {
                    return;
                }
                int i = 0;
                for (ClassTypeInfo parent : parents) {
                    monitor.checkCanceled();
                    if (parent.isAbstract() && i == 0) {
                        if (this instanceof WindowsConstructorAnalysisCmd) {
                            // skip __CheckForDebuggerJustMyCode
                            i++;
                            if (i >= functions.size()) {
                                return;
                            }
                        }
                    }
                    ClassTypeInfoUtils.getClassFunction(program, parent, functions.get(i).getEntryPoint());
                    setFunction(parent, functions.get(i), destructor);
                    i++;
                }
    }

    protected List<Function> getCalledFunctions(Function function) throws CancelledException {
        List<Function> result = new ArrayList<>();
        Instruction inst = listing.getInstructionAt(function.getEntryPoint());
        while (function.getBody().contains(inst.getAddress())) {
            monitor.checkCanceled();
            FlowType flow = inst.getFlowType();
            if (flow.isCall() && !flow.isComputed()) {
                Function callee = fManager.getFunctionAt(inst.getFlows()[0]);
                if (callee.isThunk()) {
                    callee = callee.getThunkedFunction(true);
                }
                if (callee.isExternal()) {
                    return result;
                }
                result.add(callee);
            }
            inst = inst.getNext();
        }
        return result;
    }

}
