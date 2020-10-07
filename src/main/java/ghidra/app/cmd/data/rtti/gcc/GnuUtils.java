package ghidra.app.cmd.data.rtti.gcc;

import java.util.List;
import java.util.Set;
import java.util.Collections;

import docking.Tool;
import ghidra.program.model.data.DataType;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.util.demangler.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.app.util.demangler.DemanglerUtil.demangle;
import static ghidra.plugins.fsbrowser.FSBUtils.getProgramManager;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

/**
 * Static Utility Class for GNU Binaries
 */
public final class GnuUtils {

	private static final String PTRDIFF = "ptrdiff_t";
	private static final String PPC = "PowerPC";
	private static final String CXXABI = "__cxxabiv1";
	private static final String EXTERNAL = "<EXTERNAL>";

	public static final Set<String> COMPILER_NAMES = Set.of("gcc", "default");

	private static final CategoryPath CXXABI_PATH = new CategoryPath(CategoryPath.ROOT, CXXABI);

	private GnuUtils() {
	}

	/**
	 * Gets the {@value #CXXABI} CategoryPath
	 * @return the {@value #CXXABI} CategoryPath
	 */
	public static CategoryPath getCxxAbiCategoryPath() {
		return CXXABI_PATH;
	}

	/**
	 * @param dtm the programs datatype manager
	 * @return true if LLP64 was defined
	 */
	public static boolean isLLP64(DataTypeManager dtm) {
		return dtm.getDataOrganization().getPointerSize() == 8;
	}

	private static DataType createPtrDiff(DataTypeManager dtm) {
		DataOrganization org = dtm.getDataOrganization();
		DataType dataType = AbstractIntegerDataType.getSignedDataType(org.getPointerSize(), dtm);
		return new TypedefDataType(CategoryPath.ROOT, PTRDIFF, dataType, dtm);
	}

	/**
	 * Gets the appropriate TypeDefDataType for the builtin __PTRDIFF_TYPE__
	 * @param dtm the programs datatype manager
	 * @return the appropriate TypeDefDataType for the builtin __PTRDIFF_TYPE__
	 */
	public static DataType getPtrDiff_t(DataTypeManager dtm) {
		DataType ptrdiff_t = createPtrDiff(dtm);
		if (dtm.contains(ptrdiff_t)) {
			return dtm.resolve(ptrdiff_t, KEEP_HANDLER);
		}
		return ptrdiff_t;
	}

	/**
	 * Gets the size in bytes of __PTRDIFF_TYPE__
	 * @param dtm the programs datatype manager
	 * @return the size in bytes of __PTRDIFF_TYPE__
	 */
	public static int getPtrDiffSize(DataTypeManager dtm) {
		return getPtrDiff_t(dtm).getLength();
	}

	/**
	 * Gets all MemoryBlocks in a Program which hold non-volatile data
	 * @param program the program to be searched
	 * @return A list of all memory blocks whose name contains "data" with non-volatile data
	 * @deprecated use {@link CppClassAnalyzerUtils#getAllDataBlocks(Program)}
	 */
	@Deprecated(forRemoval = true)
	public static List<MemoryBlock> getAllDataBlocks(Program program) {
		return CppClassAnalyzerUtils.getAllDataBlocks(program);
	}

	/**
	 * Returns true if this MemoryBlock has non-volatile data
	 * @param block the memory block to test
	 * @return true if this MemoryBlock has non-volatile data
	 * @deprecated use {@link CppClassAnalyzerUtils#isDataBlock(MemoryBlock)}
	 */
	@Deprecated(forRemoval = true)
	public static boolean isDataBlock(MemoryBlock block) {
		return CppClassAnalyzerUtils.isDataBlock(block);
	}

	/**
	 * Checks if a Program's language is PowerPC64
	 * @param program the program to test
	 * @return true if the program's language is PowerPC64
	 */
	public static boolean hasFunctionDescriptors(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		if (!processor.toString().contentEquals(PPC)) {
			return false;
		}
		return isLLP64(program.getDataTypeManager());
	}

	/**
	 * Checks if the Program was compiled by a GNU variant
	 * @param program the program to check
	 * @return true if compiled by a GNU variant
	 */
	public static boolean isGnuCompiler(Program program) {
		String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return COMPILER_NAMES.contains(id);
	}

	/**
	 * Checks if a function pointer is located at the specified address
	 * @param program the program containing the data
	 * @param address the address of the data
	 * @return true if a function pointer is located at the specified address
	 */
	public static boolean isFunctionPointer(Program program, Address address) {
		RelocationTable table = program.getRelocationTable();
		if (table.isRelocatable()) {
			Relocation reloc = table.getRelocation(address);
			if (reloc != null) {
				String name = reloc.getSymbolName();
				if (name != null) {
					if (name.equals(GnuVtable.PURE_VIRTUAL_FUNCTION_NAME)) {
						return true;
					}
					DemangledObject demangled = demangle(name);
					if (demangled != null && demangled instanceof DemangledFunction) {
						return true;
					}
				}
			}
		}
		Address pointee = getAbsoluteAddress(program, address);
		if (pointee == null) {
			return false;
		}
		if (hasFunctionDescriptors(program)) {
			// the PowerPC Elf64 ABI has Function Descriptors :/
			pointee = getAbsoluteAddress(program, pointee);
			if (pointee == null) {
				return false;
			}
		}
		Listing listing = program.getListing();
		if (listing.getFunctionAt(pointee) != null) {
			// takes care of external functions
			return true;
		}
		MemoryBlock block = program.getMemory().getBlock(pointee);
		return block != null ? block.isExecute() : false;
	}

	/**
	 * Checks if a null pointer is located at the specified address
	 * @param program the program containing the data
	 * @param address the address of the data
	 * @return true if a null pointer is located at the specified address
	 */
	public static boolean isNullPointer(Program program, Address address) {
		return isNullPointer(new MemoryBufferImpl(program.getMemory(), address));
	}

	/**
	 * Checks if a null pointer is located at the specified address
	 * @param buf the memory buffer containing the data
	 * @return true if a null pointer is located at the specified address
	 */
	public static boolean isNullPointer(MemBuffer buf) {
		try {
			return buf.getBigInteger(
				0, buf.getMemory().getProgram().getDefaultPointerSize(), false).longValue() == 0;
		} catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * Checks if a valid pointer is located at the specified address
	 * @param program the program containing the data
	 * @param address the address of the data
	 * @return true if a valid pointer is located at the specified address
	 */
	public static boolean isValidPointer(Program program, Address address) {
		Address pointee = getAbsoluteAddress(program, address);
		if (pointee != null) {
			return program.getMemory().getLoadedAndInitializedAddressSet().contains(pointee);
		}
		return false;
	}

	/**
	 * Checks if a valid pointer is located at the specified address
	 * @param buf the memory buffer containing the data
	 * @return true if a valid pointer is located at the specified address
	 */
	public static boolean isValidPointer(MemBuffer buf) {
		return buf != null ? isValidPointer(buf.getMemory().getProgram(), buf.getAddress()) : false;
	}

	/**
	 * Checks if a valid pointer to a .*data section address is located at the specified address
	 * @param buf the memory buffer containing the data
	 * @return true if a valid data pointer is located at the specified address
	 */
	public static boolean isDataPointer(MemBuffer buf) {
		if (isValidPointer(buf)) {
			Memory mem = buf.getMemory();
			Address pointee = getAbsoluteAddress(mem.getProgram(), buf.getAddress());
			MemoryBlock block = mem.getBlock(pointee);
			if (block != null) {
				return getAllDataBlocks(mem.getProgram()).contains(block);
			}
		}
		return false;
	}

	/**
	 * Gets all direct data references to the specified address
	 * @param program the program containing the data
	 * @param address the address of the data
	 * @return a set of all direct data references to the specified address
	 */
	public static Set<Address> getDirectDataReferences(Program program, Address address) {
		try {
			return getDirectDataReferences(program, address, new DummyCancellableTaskMonitor());
		} catch (CancelledException e) {
			return null;
		}
	}

	/**
	 * Gets all direct data references to the specified address
	 * @param program the program containing the data
	 * @param address the address of the data
	 * @param monitor the task monitor
	 * @return a set of all direct data references to the specified address
	 * @throws CancelledException if the search is cancelled
	 */
	public static Set<Address> getDirectDataReferences(Program program, Address address,
			TaskMonitor monitor) throws CancelledException {
		if (address == null)
			return Collections.emptySet();
		List<MemoryBlock> dataBlocks = getAllDataBlocks(program);
		int pointerAlignment =
			program.getDataTypeManager().getDataOrganization().getDefaultPointerAlignment();
		return ProgramMemoryUtil.findDirectReferences(program, dataBlocks,
			pointerAlignment, address, monitor);
	}

	/**
	 * Attempts to get the Program containing the data for the relocation
	 * @param program the program containing the relocation
	 * @param reloc the relocation
	 * @return the external program or null if not resolved
	 */
	public static Program getExternalProgram(Program program, Relocation reloc) {
		ExternalManager manager = program.getExternalManager();
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(reloc.getSymbolName())) {
			for (String path : symbol.getPath()) {
				Library library = manager.getExternalLibrary(path);
				if (library != null) {
					return openProgram(library.getAssociatedProgramPath());
				}
			}
		}
		// If still not found, brute force it
		for (String name : manager.getExternalLibraryNames()) {
			if (name.equals(EXTERNAL)) {
				continue;
			}
			String path = manager.getExternalLibraryPath(name);
			if (path == null) {
				continue;
			}
			Program exProgram = openProgram(path);
			if (exProgram != null) {
				Namespace global = exProgram.getGlobalNamespace();
				SymbolTable exTable = exProgram.getSymbolTable();
				if (!exTable.getSymbols(reloc.getSymbolName(), global).isEmpty()) {
					return exProgram;
				}
			}
		}
		return null;
	}

	private static Program openProgram(String path) {
		Project project = AppInfo.getActiveProject();
		DomainFile file = project.getProjectData().getFile(path);
		if (file == null) {
			return null;
		}
		Tool[] tools = project.getToolManager().getRunningTools();
		for (Tool tool : tools) {
			if (tool instanceof PluginTool) {
				return getProgramManager((PluginTool) tool, false).openProgram(file);
			}
		}
		return null;
	}

	/**
	 * Checks if the provided address is located within the {@value MemoryBlock#EXTERNAL_BLOCK_NAME}
	 * memory block.
	 * @param program the program containing the address
	 * @param address the address to check
	 * @return true if it is an external address
	 */
	public static boolean isExternal(Program program, Address address) {
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(address);
		return block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME);
	}

}
