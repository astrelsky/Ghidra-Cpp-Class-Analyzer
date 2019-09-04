package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vftable;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.getClassFunction;
import static ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils.isProcessedFunction;

public class WindowsVftableAnalysisCmd extends BackgroundCommand {

    private static final String NAME = WindowsVftableAnalysisCmd.class.getSimpleName();


    private ClassTypeInfo typeinfo;
    private Program program;

    public WindowsVftableAnalysisCmd(ClassTypeInfo type) {
        super(NAME, false, true, false);
        this.typeinfo = type;
    }

    @Override
    public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
        if (!(obj instanceof Program)) {
            String message = "Can only analyze a vtable in a program.";
            Msg.error(this, message);
            return false;
        }
        this.program = (Program) obj;
		Vftable vtable = typeinfo.getVtable();
        if (vtable.isValid()) {
            try {
                setupFunctions(vtable);
            } catch (Exception e) {
                Msg.error(this, e);
            }
        }
        return true;
    }
    
    private void setupFunctions(Vftable vftable) throws Exception {
        ClassTypeInfo type = vftable.getTypeInfo();
        if (!type.isValid()) {
            return;
        }
        Function[][] functionTables = vftable.getFunctionTables();
        for (Function[] functionTable : functionTables) {
            for (Function function : functionTable) {
                if (!isProcessedFunction(function)) {
                    Function thunkedFunction =
                        VftableAnalysisUtils.recurseThunkFunctions(program, function);
                    getClassFunction(program, type, thunkedFunction.getEntryPoint());
                }
            }
        }
    }

}