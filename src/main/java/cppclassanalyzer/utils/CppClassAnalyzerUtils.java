package cppclassanalyzer.utils;

import java.util.Arrays;
import java.util.Objects;

import ghidra.app.cmd.function.AddFunctionTagCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;

public final class CppClassAnalyzerUtils {

	public static final String CONSTRUCTOR = "CONSTRUCTOR";
	public static final String DESTRUCTOR = "DESTRUCTOR";
	public static final String DESTRUCTOR_CHAR = "~";

	private CppClassAnalyzerUtils() {
	}

	/**
	 * Gets the first PluginTool which has the provided domain object opened
	 * @param obj the domain object
	 * @return the first found PluginTool or null if none found
	 */
	public static PluginTool getTool(DomainObject obj) {
		Project project = AppInfo.getActiveProject();
		PluginTool[] tools = project.getToolManager().getRunningTools();
		return Arrays.stream(tools)
			.filter(obj::isUsedBy)
			.findFirst()
			.orElse(null);
	}

	/**
	 * Checks if the function is a default function
	 * @param function the function to check
	 * @return true if the function is a default function or if it is null
	 */
	public static boolean isDefaultFunction(Function function) {
		if (function == null || function.isThunk()) {
			return true;
		}
		String defaultName = SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
		return defaultName.equals(function.getName());
	}

	public static boolean isDestructor(Function function) {
		return function.getName().contains(DESTRUCTOR_CHAR);
	}

	public static void setConstructorDestructorTag(Function function, boolean isConstructor) {
		Objects.requireNonNull(function);
		String tag = isConstructor ? CONSTRUCTOR : DESTRUCTOR;
		String oldTag = isConstructor ? DESTRUCTOR : CONSTRUCTOR;
		AddFunctionTagCmd cmd = new AddFunctionTagCmd(tag, function.getEntryPoint());
		function.removeTag(oldTag);
		cmd.applyTo(function.getProgram());
	}

	/**
	 * Recursively creates thunked functions starting a the following potential
	 * thunked function.
	 * @param function the potential thunked function
	 * @return the thunked-to function
	 */
	public static Function createThunkFunctions(Function function) {
		Objects.requireNonNull(function);
		Program program = function.getProgram();
		FunctionManager manager = program.getFunctionManager();
		while(true) {
			Address thunkedAddress = CreateThunkFunctionCmd.getThunkedAddr(
				program, function.getEntryPoint(), false);
			if (thunkedAddress == null || thunkedAddress == Address.NO_ADDRESS) {
				// difference in ghidra versions
				break;
			}
			Function thunkedFunction = manager.getFunctionAt(thunkedAddress);
			if (thunkedFunction == null) {
				CreateFunctionCmd cmd = new CreateFunctionCmd(thunkedAddress);
				if (cmd.applyTo(program)) {
					thunkedFunction = cmd.getFunction();
				} else {
					String msg = "Failed to create function at "+thunkedAddress.toString();
					Msg.info(CppClassAnalyzerUtils.class, msg);
					return function;
				}
			}
			function.setThunkedFunction(thunkedFunction);
			function = function.getThunkedFunction(true);
		}
		return function;
	}
}
