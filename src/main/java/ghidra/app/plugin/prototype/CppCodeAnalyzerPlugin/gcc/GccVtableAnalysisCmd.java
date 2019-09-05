package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vftable;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.getClassFunction;
import static ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils.isProcessedFunction;

public class GccVtableAnalysisCmd extends BackgroundCommand {

    private static final String NAME = GccVtableAnalysisCmd.class.getSimpleName();

    private ClassTypeInfo typeinfo;
    private Program program;
    private TaskMonitor monitor;

    public GccVtableAnalysisCmd(ClassTypeInfo type) {
        super(NAME, false, true, false);
        this.typeinfo = type;
    }

    @SuppressWarnings("hiding")
    @Override
    public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
        if (!(obj instanceof Program)) {
            String message = "Can only analyze a vtable in a program.";
            Msg.error(this, message);
            return false;
        }
        this.program = (Program) obj;
        this.monitor = monitor;
        try {
            Vftable vtable = typeinfo.getVtable();
            VttModel vtt = null;
            if (vtable instanceof VtableModel) {
                vtt = VtableUtils.getVttModel(program, (VtableModel) vtable);
            }
            if (vtt != null && vtt.isValid()) {
                for (Vftable parentVtable : vtt.getConstructionVtableModels()) {
                    try {
                        setupFunctions(parentVtable);
                    } catch (Exception e) {
                        Msg.error(this, e);
                    }
                }
            }
            setupFunctions(vtable);
        } catch (Exception e) {
            Msg.error(this, e);
        }
        return true;
    }
    
    private void setupFunctions(Vftable vftable) throws Exception {
        ClassTypeInfo type = vftable.getTypeInfo();
        Function[][] functionTables = vftable.getFunctionTables();
        // Also if the function has a reference to this::vtable, then it owns the function
        for (int i = 0; i < functionTables.length; i++) {
            if (i == 0) {
                for (Function function : functionTables[i]) {
                    if (isProcessedFunction(function)) {
                        continue;
                    } getClassFunction(program, type, function.getEntryPoint());
                }
            } else {
                setupThunkFunctions(type, vftable, functionTables[i], i);
            }
        }
    }

    private void setupThunkFunctions(ClassTypeInfo type, Vftable vftable,
        Function[] functionTable, int ordinal) throws Exception {
        for (Function function : functionTable) {
            if (isProcessedFunction(function)) {
                continue;
            }
            if (CreateThunkFunctionCmd.isThunk(program, function)) {
                CreateThunkFunctionCmd cmd =
                    new CreateThunkFunctionCmd(function.getEntryPoint(), false);
                cmd.applyTo(program, monitor);
            } else {
                getClassFunction(program, type, function.getEntryPoint());
            }
        }
    }
}