package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin;

import ghidra.app.cmd.function.AddFunctionTagCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;

public class VftableAnalysisUtils {

    private static final String CONSTRUCTOR = "CONSTRUCTOR";
    private static final String DESTRUCTOR = "DESTRUCTOR";
    private static final String DESTRUCTOR_CHAR = "~";

    private static final VftableAnalysisUtils THIS = new VftableAnalysisUtils();

    private VftableAnalysisUtils() {}

    public static boolean isDestructor(Function function) {
        return function.getName().contains(DESTRUCTOR_CHAR);
    }

    public static boolean isProcessedFunction(Function function) {
        if (function == null) {
            return true;
        }
        Namespace ns = function.getParentNamespace();
        if (ns.isGlobal()) {
            String name = function.getName();
            return !(name.startsWith(Function.THUNK) || name.startsWith("FUN_"));
        } return true;
    }

    public static void setConstructorDestructorTag(Program program, Function function,
        boolean destructor) {
            AddFunctionTagCmd cmd = destructor ?
                    new AddFunctionTagCmd(DESTRUCTOR, function.getEntryPoint()) :
                    new AddFunctionTagCmd(CONSTRUCTOR, function.getEntryPoint());
            if (destructor) {
                function.removeTag(CONSTRUCTOR);
            } else {
                function.removeTag(DESTRUCTOR);
            }
            cmd.applyTo(program);
    }

    public static Function recurseThunkFunctions(Program program, Function function) {
        FunctionManager manager = program.getFunctionManager();
        while(true) {
            Address thunkedAddress = CreateThunkFunctionCmd.getThunkedAddr(
                program, function.getEntryPoint(), false);
            if (thunkedAddress == null) {
                break;
            }
            Function thunkedFunction = manager.getFunctionAt(thunkedAddress);
            if (thunkedFunction == null) {
                CreateFunctionCmd cmd = new CreateFunctionCmd(thunkedAddress);
                if (cmd.applyTo(program)) {
                    thunkedFunction = cmd.getFunction();
                } else {
                    Msg.info(THIS, "Failed to create function at "+thunkedAddress);
                    return function;
                }
            }
            function.setThunkedFunction(thunkedFunction);
            function = function.getThunkedFunction(true);
        }
        return function;
    }
}
