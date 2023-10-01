package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.listing.Data;
import cppclassanalyzer.data.TypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.*;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.FundamentalTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.docking.settings.Settings;

public class TypeInfoUtils {

	private static final Pattern LAMBDA_PATTERN = Pattern.compile("[\\$\\.]_");
	private static final String DYNLIB_VTABLE_PREFIX = "_"+VtableModel.MANGLED_PREFIX;

	private TypeInfoUtils() {
	}

	private static boolean isValidTypeName(String s) {
		Matcher matcher = LAMBDA_PATTERN.matcher(s);
		if (matcher.find()) {
			// lambda
			return true;
		}
		return s.chars().allMatch(c -> StringUtilities.isValidCLanguageChar((char) c));
	}

	/**
	 * Gets the typename for the {@value TypeInfoModel#STRUCTURE_NAME} at the specified address
	 * @param program the program to be searched
	 * @param address the address of the TypeInfo Model's DataType
	 * @return the TypeInfo's typename string or "" if invalid
	 */
	public static String getTypeName(Program program, Address address) {
		try {
			int pointerSize = program.getDefaultPointerSize();
			Address nameAddress = getAbsoluteAddress(program, address.add(pointerSize));
			if (nameAddress == null) {
				return "";
			}
			DataType dt = TerminatedStringDataType.dataType;
			Settings settings = dt.getDefaultSettings();
			MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), nameAddress);
			StringDataInstance string = new StringDataInstance(dt, settings, buf, -1);
			if (string.getStringLength() != -1) {
				string = new StringDataInstance(dt, settings, buf, string.getStringLength());
				String result = string.getStringValue();

				/*
				 * Some anonymous namespaces typename strings start with * Unfortunately the *
				 * causes issues with demangling so exclude it
				 */
				result = result.startsWith("*") ? result.substring(1) : result;
				if (isValidTypeName(result)) {
					return result;
				}
			}
		} catch (AddressOutOfBoundsException e) {
			// occured while reading assumed string, not a problem
		}
		return "";
	}

	/**
	 * Locates the TypeInfo with the specified ID_STRING
	 * @param program  the program to be searched
	 * @param typename the typename of the typeinfo to search for
	 * @param monitor  the active task monitor
	 * @return the TypeInfo with the corresponding typename or invalid if it doesn't exist
	 * @throws CancelledException if the search is cancelled
	 * @see TypeInfoModel#ID_STRING
	 */
	public static TypeInfo findTypeInfo(Program program, String typename, TaskMonitor monitor)
		throws CancelledException {
			return findTypeInfo(program, program.getAddressFactory().getAddressSet(),
								typename, monitor);
	}

	/**
	 * Locates the TypeInfo with the specified typename
	 * @param program the program to be searched
	 * @param set the address set to be searched
	 * @param typename the typename to search for
	 * @param monitor the active task monitor
	 * @return the TypeInfo with the corresponding typename or null if it doesn't exist
	 * @throws CancelledException if the search is cancelled
	 */
	public static TypeInfo findTypeInfo(Program program, AddressSetView set, String typename,
		TaskMonitor monitor) throws CancelledException {
			TypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
			TypeInfo type = getExistingTypeInfo(program, manager, typename);
			if (type != null) {
				return type;
			}
			int pointerAlignment =
				program.getDataTypeManager().getDataOrganization().getDefaultPointerAlignment();
			List<Address> stringAddresses = findTypeString(program, set, typename, monitor);
			for (Address stringAddress : stringAddresses) {
				Set<Address> references = ProgramMemoryUtil.findDirectReferences(program,
					pointerAlignment, stringAddress, monitor);
				if (references.isEmpty()) {
					continue;
				}
				for (Address reference : references) {
					Address typeinfoAddress = reference.subtract(program.getDefaultPointerSize());
					type = manager.getTypeInfo(typeinfoAddress);
					if (type == null) {
						continue;
					}
					if (type.getTypeName().equals(typename)) {
						return type;
					}
				}
			}
			return null;
	}

	private static TypeInfo getExistingTypeInfo(Program program, TypeInfoManager manager,
			String typename) {
		Namespace ns = getNamespaceFromTypeName(program, typename);
		SymbolTable table = program.getSymbolTable();
		return CollectionUtils.asStream(table.getChildren(ns.getSymbol()))
			.filter(s -> s.getName().equals(TypeInfo.SYMBOL_NAME))
			.map(Symbol::getAddress)
			.map(manager::getTypeInfo)
			.filter(Objects::nonNull)
			.findFirst()
			.orElse(null);
	}

	private static List<Address> findTypeString(Program program, AddressSetView set,
		String typename, TaskMonitor monitor) throws CancelledException {
			List<MemoryBlock> dataBlocks = CppClassAnalyzerUtils.getAllDataBlocks(program);
			List<Address> typeInfoAddresses =
				ProgramMemoryUtil.findString(typename, program, dataBlocks, set, monitor);
			return typeInfoAddresses;
	}

	private static String relocationToID(Relocation reloc) {
		String baseTypeName = reloc.getSymbolName();
		if (baseTypeName != null) {
			if (baseTypeName.contains("_ZTI")) {
				if (!baseTypeName.contains(TypeInfoModel.STRUCTURE_NAME)) {
					return FundamentalTypeInfoModel.ID_STRING;
				}
			}
			return baseTypeName.substring(4);
		}
		return null;
	}

	private static String externalSymbolToID(Program program, Address address) {
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(address)) {
			if (symbol.getName().startsWith(DYNLIB_VTABLE_PREFIX)) {
				return symbol.getName().substring(DYNLIB_VTABLE_PREFIX.length());
			}
		}
		return null;
	}
	
	static Relocation getRelocation(Program program, Address address) {
		RelocationTable table = program.getRelocationTable();
		List<Relocation> relocs = table.getRelocations(address);
		if (relocs.isEmpty()) {
			return null;
		}
		if (relocs.size() > 1) {
			String msg = "Multiple relocations at " + address.toString();
			Msg.warn(TypeInfoUtils.class, msg);
		}
		return relocs.get(0);
	}

	/**
	 * Gets the identifier string for the {@value TypeInfoModel#STRUCTURE_NAME}
	 * at the specified address.
	 * @param program the program to be searched
	 * @param address the address of the TypeInfo Model's DataType
	 * @return The TypeInfo's identifier string or "" if invalid
	 * @see TypeInfoModel#ID_STRING
	 */
	public static String getIDString(Program program, Address address) {
		Relocation reloc = getRelocation(program, address);
		if (reloc != null && reloc.getSymbolName() != null) {
			if (reloc.getSymbolName().startsWith(VtableModel.MANGLED_PREFIX)) {
				return reloc.getSymbolName().substring(VtableModel.MANGLED_PREFIX.length());
			}
			Address relocationAddress = getAbsoluteAddress(program, address);
			if (relocationAddress == null || relocationAddress.getOffset() == 0) {
				return "";
			}
			MemoryBlock block = program.getMemory().getBlock(relocationAddress);
			if (block == null || !block.isInitialized()) {
				String name = relocationToID(reloc);
				if (name != null) {
					return name;
				}
			}
		} else {
			Address relocAddress = getAbsoluteAddress(program, address);
			if (relocAddress != null) {
				Data data = program.getListing().getDataContaining(relocAddress);
				if (data != null) {
					reloc = getRelocation(program, data.getAddress());
					if (reloc != null) {
						String name = relocationToID(reloc);
						if (name != null) {
							return name;
						}
					}
				}
				String name = externalSymbolToID(program, relocAddress);
				if (name != null) {
					return name;
				}
			}
		}
		final int POINTER_SIZE = program.getDefaultPointerSize();
		Address baseVtableAddress = getAbsoluteAddress(program, address);
		if (baseVtableAddress == null || baseVtableAddress.getOffset() == 0) {
			return "";
		}
		Address baseTypeInfoAddress = getAbsoluteAddress(
			program, baseVtableAddress.subtract(POINTER_SIZE));
		if (baseTypeInfoAddress == null) {
			return "";
		}
		return getTypeName(program, baseTypeInfoAddress);
	}

	/**
	 * Checks if a typeinfo* is located at the specified address
	 * @param program the program to be searched
	 * @param address the address of the suspected pointer
	 * @return true if a typeinfo* is present at the address
	 */
	public static boolean isTypeInfoPointer(Program program, Address address) {
		Address pointee = getAbsoluteAddress(program, address);
		if (pointee == null) {
			return false;
		}
		return isTypeInfo(program, pointee);
	}

	/**
	 * Checks if a typeinfo* is present at the buffer's address
	 * @param buf the buffer containing the data
	 * @return true if a typeinfo* is present at the buffer's address
	 */
	public static boolean isTypeInfoPointer(MemBuffer buf) {
		return buf != null ?
			isTypeInfoPointer(buf.getMemory().getProgram(), buf.getAddress()) : false;
	}

	/**
	 * Checks if a valid TypeInfo is located at the address in the program.
	 * @param program the program containing the TypeInfo
	 * @param address the address of the TypeInfo
	 * @return true if the buffer contains a valid TypeInfo
	 * @deprecated please use {@link TypeInfoManager#isTypeInfo(Address)}
	 */
	@Deprecated(since = "1.5", forRemoval = true)
	public static boolean isTypeInfo(Program program, Address address) {
		/* Makes more sense to have it in this utility, but more convient to check
		   if it is valid or not within the factory */
		TypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
		return manager.isTypeInfo(address);
	}

	/**
	 * Checks if a valid TypeInfo is located at the start of the buffer
	 * @param buf the memory buffer containing the TypeInfo data
	 * @return true if the buffer contains a valid TypeInfo
	 * @deprecated please use {@link TypeInfoManager#isTypeInfo(Address)}
	 */
	@Deprecated(since = "1.5", forRemoval = true)
	public static boolean isTypeInfo(MemBuffer buf) {
		return isTypeInfo(buf.getMemory().getProgram(), buf.getAddress());
	}

	/**
	 * Gets the Namespace for the corresponding typeinfo
	 * @param program the program containing the namespace
	 * @param type the typeinfo
	 * @return the Namespace for the corresponding typeinfo
	 */
	public static Namespace getNamespaceFromTypeName(Program program, TypeInfo type) {
		int id = -1;
		String typename = type.getTypeName();
		if (program.getCurrentTransactionInfo() == null) {
			id = program.startTransaction("Creating namespace for " + typename);
		}
		try {
			Namespace ns;
			if (!(type instanceof ClassTypeInfo)) {
				ns = getFundamentalNamespace(program, typename);
			} else {
				ns = getNamespaceFromTypeName(program, typename);
			}
			if (id != -1) {
				program.endTransaction(id, true);
			}
			return ns;
		} catch (InvalidInputException e) {
			if (id != -1) {
				program.endTransaction(id, false);
			}
			throw new AssertException(e);
		}
	}

	private static Namespace getFundamentalNamespace(Program program, String typename)
			throws InvalidInputException {
		String mangled = typename.startsWith("_ZTI") ? typename : "_ZTI" + typename;
		Demangled demangled = DemanglerUtil.demangle(program, mangled);
		String signature = demangled.getNamespace().getSignature().replaceAll("_\\[", "[");
		signature = SymbolUtilities.replaceInvalidChars(signature, true);
		return NamespaceUtils.createNamespaceHierarchy(
			signature, null, program, SourceType.ANALYSIS);
	}

	/**
	 * Gets the Namespace for the corresponding typename
	 * @param program the program containing the namespace
	 * @param typename the typename corresponding to the namespace
	 * @return the Namespace for the corresponding typename
	 */
	public static Namespace getNamespaceFromTypeName(Program program, String typename) {
		String mangled = typename.startsWith("_ZTI") ? typename : "_ZTI" + typename;
		Demangled demangled = DemanglerUtil.demangle(program, mangled);
		if (demangled == null) {
			throw new AssertException("Failed to demangle " + typename);
		}
		Namespace ns =  DemangledObject.createNamespace(
			program, demangled.getNamespace(), program.getGlobalNamespace(), false);
		if (ns.isGlobal()) {
			throw new AssertException("Global Namespace returned!");
		}
		return ns;
	}
	
	/**
	 * Retrieves the CategoryPath for the represented datatype
	 * @param type the TypeInfo
	 * @return the TypeInfo's datatype CategoryPath
	 */
	public static CategoryPath getCategoryPath(TypeInfo type) {
		Namespace ns = type.getNamespace().getParentNamespace();
		String path;
		if (ns.isGlobal()) {
			path = "";
		} else {
			path = Namespace.DELIMITER+ns.getName(true);
		}
		path = path.replaceAll(Namespace.DELIMITER, CategoryPath.DELIMITER_STRING);
		return new CategoryPath(path);
	}

	/**
	 * Retrieves the DataTypePath for the represented datatype
	 * @param type the TypeInfo
	 * @return the TypeInfo's datatype DataTypePath
	 */
	public static DataTypePath getDataTypePath(TypeInfo type) {
		return new DataTypePath(getCategoryPath(type), type.getName());
	}

	/**
	 * Generates an appropriate error message for when an invalid type_info is encountered
	 *
	 * @param program the program containing the data
	 * @param address the address of the data
	 * @param id the expected type_info identification string
	 * @return an appropriate error message
	 */
	public static String getErrorMessage(Program program, Address address, String id) {
		StringBuilder builder = new StringBuilder("Exception caused by Ghidra-Cpp-Class-Analyzer\n");
		builder.append(String.format("The TypeInfo at %s is not valid\n", address));
		builder.append(
			String.format("Expected %s to match identifier %s\n",
						  getIDString(program, address),
						  id))
			   .append("Potential typename: ")
			   .append(getTypeName(program, address));
		Relocation reloc = getRelocation(program, address);
		if (reloc != null) {
			builder.append(String.format(
				"\nrelocation at %s to symbol %s", reloc.getAddress(), reloc.getSymbolName()));
		}
		return builder.toString();
	}

	/**
	 * Gets the program this TypeInfo is in
	 *
	 * @param type the TypeInfo
	 * @return the program containing the TypeInfo
	 */
	public static Program getProgram(TypeInfo type) {
		return type.getNamespace().getSymbol().getProgram();
	}


	private static boolean isMangled(String s) {
		return s.startsWith("_ZTI") && !s.contains("@");
	}

	/**
	 * Gets the symbol name for the ClassTypeInfo
	 *
	 * @param type the ClassTypeInfo
	 * @return the type info symbol nane
	 */
	public static String getSymbolName(TypeInfo type) {
		Program program = getProgram(type);
		SymbolTable table = program.getSymbolTable();
		return Arrays.stream(table.getSymbols(type.getAddress()))
			.map(Symbol::getName)
			.filter(TypeInfoUtils::isMangled)
			.findFirst()
			.orElse("_ZTI" + type.getTypeName());
	}

	private static Address getAbsoluteAddress(Program program, Address address) {
		Memory mem = program.getMemory();
		if (!mem.contains(address)) {
			return null;
		}
		try {
			Address pointee = MSDataTypeUtils.getAbsoluteAddress(program, address);
			if (pointee != null && mem.contains(pointee)) {
				return pointee;
			}
		} catch (NullPointerException e) {
			// don't care
		}
		return null;
	}

}
