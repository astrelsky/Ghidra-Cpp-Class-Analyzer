package cppclassanalyzer.utils;

import java.util.*;
import java.util.function.Predicate;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.function.AddFunctionTagCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.plugin.HeadlessClassTypeInfoManagerService;
import cppclassanalyzer.service.ClassTypeInfoManagerService;

import static ghidra.util.SystemUtilities.isInHeadlessMode;

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
		for (Object o : obj.getConsumerList()) {
			if (o instanceof PluginTool) {
				return (PluginTool) o;
			}
		}
		return null;
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
		if (!function.getParentNamespace().isGlobal()) {
			return false;
		}
		String defaultName = SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
		return defaultName.equals(function.getName());
	}

	/**
	 * Checks if the function is a destructor
	 * @param function the function to check
	 * @return true if the function is a desructor
	 */
	public static boolean isDestructor(Function function) {
		return function.getName().contains(DESTRUCTOR_CHAR);
	}

	/**
	 * Sets the Constructor/Destructor tags for the function
	 * @param function the function
	 * @param isConstructor true if the function is a constructor
	 */
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

	public static ClassTypeInfoManagerService getService(Program program) {
		if (isInHeadlessMode()) {
			return HeadlessClassTypeInfoManagerService.getInstance();
		}
		PluginTool tool = getTool(program);
		if (tool == null) {
			return null;
		}
		return tool.getService(ClassTypeInfoManagerService.class);
	}

	/**
	 * Gets the ClassTypeInfoManager for the specified program
	 * @param program the program
	 * @return the program's ClassTypeInfoManager
	 */
	public static ProgramClassTypeInfoManager getManager(Program program) {
		ClassTypeInfoManagerService service;
		if (isInHeadlessMode()) {
			service = HeadlessClassTypeInfoManagerService.getInstance();
		} else {
			service = getService(program);
		}
		return service.getManager(program);
	}

	/**
	 * Gets all MemoryBlocks in a Program which hold non-volatile data
	 * @param program the program to be searched
	 * @return A list of all memory blocks whose name contains "data" with non-volatile data
	 */
	public static List<MemoryBlock> getAllDataBlocks(Program program) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		ArrayList<MemoryBlock> dataBlocks = new ArrayList<>(blocks.length);
		for (MemoryBlock block : blocks) {
			if (isDataBlock(block) && isDataBlockName(block)) {
				if (!block.isVolatile()) {
					dataBlocks.add(block);
				}
			}
		}
		dataBlocks.trimToSize();
		return dataBlocks;
	}

	private static boolean isDataBlockName(MemoryBlock block) {
		String name = block.getName().toLowerCase();
		return name.contains("data") || name.equals(".bss") || name.contains("__const");
	}

	/**
	 * Returns true if this MemoryBlock has non-volatile data
	 * @param block the memory block to test
	 * @return true if this MemoryBlock has non-volatile data
	 */
	public static boolean isDataBlock(MemoryBlock block) {
		return block != null ? block.isRead() || block.isWrite() : false;
	}

	public static boolean isAbstract(ClassTypeInfo type, String pureVirtualFunctionName) {
		Vtable vtable = type.getVtable();
		if (!Vtable.isValid(vtable)) {
			return false;
		}
		AbstractFunctionChecker checker = new AbstractFunctionChecker(pureVirtualFunctionName);
		return Arrays.stream(vtable.getFunctionTables())
			.flatMap(Arrays::stream)
			.anyMatch(checker);
	}

	private static final class AbstractFunctionChecker implements Predicate<Function> {

		private final String fName;

		AbstractFunctionChecker(String fName) {
			this.fName = fName;
		}

		@Override
		public boolean test(Function f) {
			// f can only be null if the class is abstract
			return f != null ? f.getName().equals(fName) : true;
		}
	}
}
