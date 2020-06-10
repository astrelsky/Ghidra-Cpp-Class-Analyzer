package ghidra.app.cmd.data.rtti.gcc;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

import docking.Tool;
import ghidra.program.model.data.DataType;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledAddressTable;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.gnu.GnuDemanglerNativeProcess;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.datastruct.IntSet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.LanguageIdHandler;

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
	public static final String PURE_VIRTUAL_FUNCTION_NAME = "__cxa_pure_virtual";

	private static final CategoryPath CXXABI_PATH = new CategoryPath(CategoryPath.ROOT, CXXABI);
	private static final Pattern DESCRIPTIVE_PREFIX_PATTERN =
		Pattern.compile("((?:(.+) )+(for|to) )(.+)");
	private static final Pattern TRAILING_NUMBER_PATTERN = Pattern.compile(".+?(\\d+)$");

	private static final Map<String, IntSet> COPY_RELOCATIONS = Map.of(
		"x86", new IntSet(new int[]{5}),
		"sparc", new IntSet(new int[]{19}),
		"RISCV", new IntSet(new int[]{4}),
		"PowerPC", new IntSet(new int[]{19}),
		"MIPS", new IntSet(new int[]{126}),
		"ARM", new IntSet(new int[]{20}),
		"AARCH64", new IntSet(new int[]{180, 1024})
	);

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
	 */
	public static List<MemoryBlock> getAllDataBlocks(Program program) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		List<MemoryBlock> dataBlocks = new ArrayList<MemoryBlock>();
		for (MemoryBlock block : blocks) {
			if (isDataBlock(block) && isDataBlockName(block)) {
				if (!block.isVolatile()) {
					dataBlocks.add(block);
				}
			}
		}
		return dataBlocks;
	}

	private static boolean isDataBlockName(MemoryBlock block) {
		String name = block.getName();
		return name.contains("data") || name.equals(".bss");
	}

	/**
	 * Returns true if this MemoryBlock has non-volatile data
	 * @param block the memory block to test
	 * @return true if this MemoryBlock has non-volatile data
	 */
	public static boolean isDataBlock(MemoryBlock block) {
		return block != null ? block.isRead() || block.isWrite() : false;
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
					if (name.equals(PURE_VIRTUAL_FUNCTION_NAME)) {
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
	 *
	 * @return true if it is an external address
	 */
	public static boolean isExternal(Program program, Address address) {
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(address);
		return block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME);
	}

	/**
	 * Gets the unparsed demangled output from the native GnuDemangler
	 * @param mangled the mangled input for the demangler
	 * @return the unmodified demangled string
	 * @throws IOException if an error occurs from the native GnuDemangler process
	 */
	public static String getRawDemangledString(String mangled) throws IOException {
		GnuDemanglerNativeProcess process = GnuDemanglerNativeProcess.getDemanglerNativeProcess();
		return process.demangle(mangled).trim();
	}

	public static Demangled getSpecialDemangled(String mangled) {
		try {
			Demangled demangled = demangle(mangled);
			String output = GnuUtils.getRawDemangledString(mangled);
			Matcher matcher = DESCRIPTIVE_PREFIX_PATTERN.matcher(output);
			if (!matcher.matches()) {
				throw new AssertException("Regex should have matched: " + output);
			}
			DemangledAddressTable table =
				new DemangledAddressTable(mangled, output, matcher.group(2), true);
			table.setSignature(output);
			demangled = demangled.getNamespace();
			matcher = TRAILING_NUMBER_PATTERN.matcher(matcher.group(4));
			if (matcher.matches()) {
				demangled.setName(demangled.getName()+matcher.group(1));
			}
			table.setNamespace(demangled);
			return table;
		} catch (IOException e) {
			return null;
		}
	}

	public static boolean isCopyRelocation(Program program, int type) {
		LanguageIdHandler handler = new LanguageIdHandler(program.getLanguageID());
		if (COPY_RELOCATIONS.containsKey(handler.getProcessor())) {
			return COPY_RELOCATIONS.get(handler.getProcessor()).contains(type);
		}
		return false;
	}

}
