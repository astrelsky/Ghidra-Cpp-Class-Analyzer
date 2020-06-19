package ghidra.app.cmd.data.rtti.gcc;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.BaseClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.XReferenceUtil;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.GnuClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB.TypeId;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.SpecialAddress;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ClassTypeInfoUtils {

	private static final String PLACEHOLDER_DESCRIPTION = "PlaceHolder Class Structure";
	private static final String MISSING = "Missing";

	private ClassTypeInfoUtils() {
	}

	/**
	 * Finds the Vtable for the corresponding TypeInfo
	 *
	 * @param program the program to be searched
	 * @param address the address of the TypeInfo Model's DataType
	 * @param monitor the taskmonitor to be used while searching for the vtable
	 * @return The TypeInfo's Vtable Model or null if none exists
	 * @throws CancelledException if the search is cancelled
	 */
	public static Vtable findVtable(Program program, Address address, TaskMonitor monitor)
		throws CancelledException {
			ProgramClassTypeInfoManager manager = getManager(program);
			ClassTypeInfo type = manager.getType(address);
			if (type != null) {
				return findVtable(program, type, monitor);
			}
			return Vtable.NO_VTABLE;
	}

	/**
	 * Finds the Vtable for the corresponding TypeInfo
	 *
	 * @param program the program to be searched
	 * @param type the typeinfo to find the vtable for
	 * @param monitor the taskmonitor to be used while searching for the vtable
	 * @return The TypeInfo's Vtable Model or null if none exists
	 * @throws CancelledException if the search is cancelled
	 */
	public static Vtable findVtable(Program program, ClassTypeInfo type, TaskMonitor monitor)
		throws CancelledException {
			SymbolTable table = program.getSymbolTable();
			Listing listing = program.getListing();
			for (Symbol symbol : table.getChildren(type.getNamespace().getSymbol())) {
				if (symbol.getName().equals(VtableModel.SYMBOL_NAME)) {
					try {
						return new VtableModel(program, symbol.getAddress(), type);
					} catch (InvalidDataTypeException e) {
						break;
					}
				}
			}
			Set<Address> references = Collections.emptySet();
			Data tiData = listing.getDataAt(type.getAddress());
			if (tiData != null) {
				references = Arrays.stream(XReferenceUtil.getXRefList(tiData))
					.filter(Predicate.not(SpecialAddress.class::isInstance))
					.collect(Collectors.toSet());
				if (!references.isEmpty()) {
					Vtable vtable = getValidVtable(program, references, monitor, type);
					if (Vtable.isValid(vtable)) {
						return vtable;
					}
				}
			}
			references = GnuUtils.getDirectDataReferences(program, type.getAddress());
			return getValidVtable(program, references, monitor, type);
	}

	private static boolean invalidData(Data data) {
		if (data == null) {
			return false;
		}
		if (data.getDataType() instanceof Pointer) {
			return false;
		}
		if (data.getDataType() instanceof DefaultDataType) {
			return false;
		}
		return true;
	}

	private static Vtable getValidVtable(Program program, Set<Address> references,
		TaskMonitor monitor, ClassTypeInfo typeinfo) throws CancelledException {
		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		DataType ptrDiff = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
		Scalar zero = new Scalar(ptrDiff.getLength(), 0);
		boolean hasPureVirtual = program.getSymbolTable().getSymbols(
			PURE_VIRTUAL_FUNCTION_NAME).hasNext();
		for (Address reference : references) {
			monitor.checkCanceled();
			MemBuffer buf = new DumbMemBufferImpl(mem, reference.subtract(ptrDiff.getLength()));
			Object value = ptrDiff.getValue(
				buf, ptrDiff.getDefaultSettings(), ptrDiff.getLength());
			if(!zero.equals(value)) {
				continue;
			}
			Data data = listing.getDataContaining(reference);
			if (invalidData(data)) {
				continue;
			}
			try {
				final VtableModel vtable = new VtableModel(program, reference, typeinfo);
				final Function[][] functionTables = vtable.getFunctionTables();
				if (functionTables.length > 0) {
					if (functionTables[0].length > 0) {
						if (functionTables[0][0] == null) {
							for (Function function : functionTables[0]) {
								if (function == null) {
									continue;
								} if (hasPureVirtual) {
									if (PURE_VIRTUAL_FUNCTION_NAME.equals(function.getName())) {
										return vtable;
									}
								} else {
									return vtable;
								}
							}
							// construction vtable
							continue;
						}
					}
				}
				return vtable;
			} catch (InvalidDataTypeException e) {
				continue;
			}
		}
		return VtableModel.NO_VTABLE;
	}

	/**
	 * Gets the placeholder struct for a ClassTypeInfo in a specified DataTypeManager
	 * @param type the ClassTypeInfo
	 * @param dtm the DataTypeManager
	 * @return the placeholder struct for a ClassTypeInfo in a specified DataTypeManager
	 */
	public static Structure getPlaceholderStruct(ClassTypeInfo type, DataTypeManager dtm) {
		int id = dtm.startTransaction("getting placeholder struct for "+type.getName());
		CategoryPath path = TypeInfoUtils.getDataTypePath(type).getCategoryPath();
		DataType struct = dtm.getDataType(path, type.getName());
		DataType thiscallStruct =
			VariableUtilities.findOrCreateClassStruct(type.getGhidraClass(), dtm);
		if (struct == null) {
			if (isCorrectDataTypePath(thiscallStruct, type)) {
				struct = thiscallStruct;
			} else {
				struct = new StructureDataType(path, type.getName(), 0, dtm);
				struct = dtm.resolve(struct, DataTypeConflictHandler.KEEP_HANDLER);
			}
		}
		if (!struct.equals(thiscallStruct)) {
			String msg = "Variable Utils returned wrong class structure! " + type.getName();
			Msg.info(ClassTypeInfoUtils.class, msg);
		}
		dtm.endTransaction(id, true);
		return (Structure) struct;
	}

	private static boolean isCorrectDataTypePath(DataType struct, ClassTypeInfo type) {
		if (struct.getCategoryPath().getPath().contains("DWARF")) {
			// short circuit
			return true;
		}
		CategoryPath path = TypeInfoUtils.getDataTypePath(type).getCategoryPath();
		DataTypePath dtPath = struct.getDataTypePath();
		return dtPath.getCategoryPath().equals(path)
			&& dtPath.getDataTypeName().equals(type.getName());
	}

	/**
	 * Returns true if the Structure is a "placeholder" structure.
	 *
	 * @param struct the Structure to check.
	 * @return true if the Structure is a "placeholder" structure.
	 */
	public static boolean isPlaceholder(Structure struct) {
		if (struct == null) {
			return true;
		}
		String description = struct.getDescription();
		return description.equals(PLACEHOLDER_DESCRIPTION) || description.startsWith(MISSING);
	}

	/**
	 * Gets the function for the ClassTypeInfo at the specified address.
	 *
	 * @param program the Program the function is in.
	 * @param type the ClassTypeInfo for the function.
	 * @param address the Address of the function.
	 * @return the requested ClassTypeInfo's function.
	 */
	public static Function getClassFunction(Program program, ClassTypeInfo type, Address address) {
		Listing listing = program.getListing();
		FunctionManager functionManager = program.getFunctionManager();
		if (listing.getInstructionAt(address) == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			cmd.applyTo(program);
		}
		if (!functionManager.isInFunction(address)) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(address, true);
			if (!cmd.applyTo(program)) {
				return null;
			}
		}
		Function function = functionManager.getFunctionContaining(address);
		if (listing.getInstructionAt(function.getEntryPoint()) == null) {
			DisassembleCommand cmd =
				new DisassembleCommand(function.getEntryPoint(), null, true);
			cmd.applyTo(program);
		}
		try {
			function.setParentNamespace(type.getGhidraClass());
			function.setCallingConvention(GenericCallingConvention.thiscall.getDeclarationName());
			// necessary due to ghidra bug.
			function.setCustomVariableStorage(true);
			function.setCustomVariableStorage(false);
			return function;
		} catch (Exception e) {
			throw new AssertException(String.format(
				"Failed to retrieve class function for %s at %s", type, address), e);
		}
	}

	/**
	 * Sets the provided function to be a class function for the provided type
	 * @param type the class type
	 * @param function the function
	 */
	public static void setClassFunction(ClassTypeInfo type, Function function) {
		Objects.requireNonNull(type);
		Objects.requireNonNull(function);
		Address entry = function.getEntryPoint();
		if (function.getBody().getNumAddresses() <= 1) {
			DisassembleCommand cmd =
				new DisassembleCommand(entry, null, true);
			cmd.applyTo(function.getProgram());
		}
		boolean success = false;
		int id = function.getProgram().startTransaction(
			String.format("Setting class function for %s at %s", type, entry));
		try {
			function.setParentNamespace(type.getGhidraClass());
			function.setCallingConvention(GenericCallingConvention.thiscall.getDeclarationName());
			// necessary due to ghidra bug.
			//function.setCustomVariableStorage(true);
			//function.setCustomVariableStorage(false);
			success = true;
		} catch (Exception e) {
			throw new AssertException(String.format(
				"Failed to retrieve class function for %s at %s", type, entry), e);
		} finally {
			function.getProgram().endTransaction(id, success);
		}
	}

	/**
	 * Sorts a list of classes in order of most derived
	 * @param program the program containing the list of ClassTypeInfo
	 * @param classes the list of ClassTypeInfo
	 * @param monitor the task monitor
	 * @throws CancelledException is the operation is cancelled
	 */
	public static void sortByMostDerived(Program program, List<ClassTypeInfo> classes,
		TaskMonitor monitor) throws CancelledException {
			Set<ClassTypeInfo> classSet = new LinkedHashSet<>(classes);
			List<ClassTypeInfo> sortedClasses = new ArrayList<>(classes.size());
			Iterator<ClassTypeInfo> classIterator = classSet.iterator();
			while (classIterator.hasNext()) {
				monitor.checkCanceled();
				ClassTypeInfo type = classIterator.next();
				ArrayDeque<ClassTypeInfo> stack = new ArrayDeque<>();
				stack.push(type);
				while(!stack.isEmpty()) {
					monitor.checkCanceled();
					ClassTypeInfo classType = stack.pop();
					if (classType.hasParent() && classSet.contains(classType)) {
						ClassTypeInfo parent = classType.getParentModels()[0];
						if (classSet.contains(parent)) {
							stack.push(classType);
							stack.push(parent);
							continue;
						}
					}
					sortedClasses.add(classType);
					classSet.remove(classType);
				} classIterator = classSet.iterator();
			}
			classes.clear();
			classes.addAll(sortedClasses);
	}

	/**
	 * Gets the DataType representation of the _vptr for the specified ClassTypeInfo.
	 * @param program the program containing the ClassTypeInfo
	 * @param type the ClassTypeInfo
	 * @return the ClassTypeInfo's _vptr DataType
	 */
	public static DataType getVptrDataType(Program program, ClassTypeInfo type) {
		return getVptrDataType(program, type, null);
	}

	/**
	 * Gets the DataType representation of the _vptr for the specified ClassTypeInfo.
	 * @param program the program containing the ClassTypeInfo
	 * @param type the ClassTypeInfo
	 * @param path The category path to place the datatype in.
	 * @return the ClassTypeInfo's _vptr DataType
	 */
	public static DataType getVptrDataType(Program program, ClassTypeInfo type, CategoryPath path) {
		try {
			Vtable vtable = type.getVtable();
			if (path == null) {
				path = TypeInfoUtils.getDataTypePath(type).getCategoryPath();
			}
			path = new CategoryPath(path, type.getName());
			DataTypeManager dtm = program.getDataTypeManager();
			Structure struct = new StructureDataType(path, VtableModel.SYMBOL_NAME, 0, dtm);
			Function[][] functionTable = vtable.getFunctionTables();
			int pointerSize = program.getDefaultPointerSize();
			if (functionTable.length > 0 && functionTable[0].length > 0) {
				for (Function function : functionTable[0]) {
					if (function != null) {
						if (function.getName().equals(PURE_VIRTUAL_FUNCTION_NAME)) {
							struct.add(dtm.getPointer(VoidDataType.dataType), pointerSize,
									   PURE_VIRTUAL_FUNCTION_NAME, null);
							continue;
						}
						DataType dt = new FunctionDefinitionDataType(function, false);
						dt.setCategoryPath(path);
						if (dtm.contains(dt)) {
							dt = dtm.getDataType(dt.getDataTypePath());
						} else {
							dt = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
						}
						struct.add(dtm.getPointer(dt), pointerSize, function.getName(), null);
					} else {
						DataType dt = new PointerDataType(null, pointerSize, dtm);
						struct.add(dt);
					}
				}
			}
			struct = (Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
			return dtm.getPointer(struct, program.getDefaultPointerSize());
		} catch (DuplicateNameException e) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: "+e.getMessage(), e);
		}
	}

	/**
	 * Determines if the class is an abstract base
	 *
	 * @param type the __class_type_info to check
	 * @return true if abstract
	 */
	public static boolean isAbstract(ClassTypeInfo type) {
		Vtable vtable = type.getVtable();
		if (!Vtable.isValid(vtable)) {
			return false;
		}
		for (Function[] functionTable : vtable.getFunctionTables()) {
			for (Function function : functionTable) {
				if (function == null || function.getName().equals(PURE_VIRTUAL_FUNCTION_NAME)) {
					return true;
				}
			}
		}
		return false;
	}

	public static Map<ClassTypeInfo, Integer> getBaseOffsets(ClassTypeInfo type) {
		if (!type.hasParent()) {
			return Collections.emptyMap();
		}
		if (type.getParentModels().length == 1) {
			if (Vtable.isValid(type.getVtable())) {
				GnuVtable vtable = (GnuVtable) type.getVtable();
				long offset = vtable.getOffset(0, 0);
				if (offset < Long.MAX_VALUE && offset > 0) {
					return Map.of(type.getParentModels()[0], (int) offset);
				}
			}
			return Map.of(type.getParentModels()[0], 0);
		}
		if (type instanceof VmiClassTypeInfoModel) {
			VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) type;
			List<Long> offsets = vmi.getOffsets();
			ClassTypeInfo[] parents = vmi.getParentModels();
			Map<ClassTypeInfo, Integer> result = new HashMap<>(parents.length);
			for (int i = 0; i < parents.length; i++) {
				result.put(parents[i], offsets.get(i).intValue());
			}
			return result;
		}
		throw new IllegalArgumentException("Ghidra-Cpp-Class-Analyzer: type must be a GNU ClassTypeInfo");
	}

	public static GhidraClass getGhidraClassFromTypeName(Program program, String typename) {
		Namespace ns = TypeInfoUtils.getNamespaceFromTypeName(program, typename);
		if (ns instanceof GhidraClass) {
			return (GhidraClass) ns;
		}
		try {
			if (!ns.isGlobal()) {
				return NamespaceUtils.convertNamespaceToClass(ns);
			}
		} catch (InvalidInputException e) {
			// impossible
			throw new AssertException(e);
		}
		throw new AssertException(
			"Ghidra-Cpp-Class-Analyzer: failed to get GhidraClass from typename "
			+ typename);
	}

	/**
	 * Gets the ClassTypeInfoManager for the specified program
	 *
	 * @return the program's ClassTypeInfoManager
	 */
	public static ProgramClassTypeInfoManager getManager(Program program) {
		return (ProgramClassTypeInfoManager) TypeInfoUtils.getManager(program);
	}

	public static int getMaxVtableCount(ClassTypeInfo type) {
		if (type instanceof VmiClassTypeInfoModel) {
			return doGetMaxVtableCount(type);
		}
		if (type instanceof GnuClassTypeInfoDB) {
			if (((GnuClassTypeInfoDB) type).getTypeId() == TypeId.VMI_CLASS) {
				return doGetMaxVtableCount(type);
			}
		}
		return type.getVirtualParents().size()+1;
	}

	private static int doGetMaxVtableCount(ClassTypeInfo type) {
		Program program = type.getGhidraClass().getSymbol().getProgram();
		int defaultMax = type.getVirtualParents().size()+1;
		BaseClassTypeInfoModel[] bases;
		if (type instanceof VmiClassTypeInfoModel) {
			// vmi already has it constructed so check first
			bases = ((VmiClassTypeInfoModel) type).getBases();
		} else {
			bases = VmiClassTypeInfoModel.getBases(program, type.getAddress());
		}
		int offset = Arrays.stream(bases)
			.map(BaseClassTypeInfoModel::getVirtualBases)
			.flatMap(Set::stream)
			.mapToInt(BaseClassTypeInfoModel::getOffset)
			.min()
			.orElse(0);
		if (offset >= 0) {
			return type.getVirtualParents().size()+1;
		}
		return Math.max(defaultMax, Math.abs(offset) / program.getDefaultPointerSize() - 1);
	}

}
