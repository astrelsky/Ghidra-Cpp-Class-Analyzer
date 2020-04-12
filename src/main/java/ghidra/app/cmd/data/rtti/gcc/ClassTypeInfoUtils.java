package ghidra.app.cmd.data.rtti.gcc;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.XReferenceUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ClassTypeInfoUtils {

    private static final String PLACEHOLDER_DESCRIPTION = "PlaceHolder Class Structure";
    private static final String MISSING = "Missing";
    private static final CategoryPath DWARF = new CategoryPath(CategoryPath.ROOT, "DWARF");
    private static final String GENERIC_CPP_LIB = "generic_c++lib";
    private static final String GENERIC_CPP_LIB64 = GENERIC_CPP_LIB+"_64";

    private ClassTypeInfoUtils() {
    }

    /**
     * Finds the Vtable for the corresponding TypeInfo.
     * 
     * @param program the program to be searched.
     * @param address the address of the TypeInfo Model's DataType.
     * @param monitor the taskmonitor to be used while searching for the vtable
     * @return The TypeInfo's Vtable Model or null if none exists
	 * @throws CancelledException if the search is cancelled
     */
    public static Vtable findVtable(Program program, Address address, TaskMonitor monitor)
        throws CancelledException {
            SymbolTable table = program.getSymbolTable();
            Listing listing = program.getListing();
            TypeInfo typeinfo = TypeInfoFactory.getTypeInfo(program, address);
            if (!(typeinfo instanceof ClassTypeInfo)) {
                return Vtable.NO_VTABLE;
            }
            ClassTypeInfo type = (ClassTypeInfo) typeinfo;
            for (Symbol symbol : table.getChildren(typeinfo.getNamespace().getSymbol())) {
                if (symbol.getName().equals(VtableModel.SYMBOL_NAME)) {
                    try {
                        return new VtableModel(program, symbol.getAddress());
                    } catch (InvalidDataTypeException e) {
                        break;
                    }
                }
            }
            Set<Address> references = Collections.emptySet();
            Data tiData = listing.getDataAt(address);
            if (tiData != null) {
                List<Address> referenceList = Arrays.asList(XReferenceUtil.getXRefList(tiData));
                references = GnuUtils.getDirectDataReferences(program, address);
                references.removeAll(referenceList);
            }
            if (references.isEmpty()) {
                references = GnuUtils.getDirectDataReferences(program, address);
            }
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
		Msg.trace(ClassTypeInfoUtils.class,
			"Unable to find vtable for "+typeinfo.getNamespace().getName(true));
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
		struct = VariableUtilities.findOrCreateClassStruct(type.getGhidraClass(), dtm);
		DataTypePath dtPath = struct.getDataTypePath();
		if (!isDebug(dtPath)) {
			DataTypeManager cppDtm = getCppDataTypeManager(dtm);
			if (cppDtm == null) {
				cppDtm = dtm;
			}
			struct = VariableUtilities.findExistingClassStruct(type.getGhidraClass(), cppDtm);
			if (struct != null && path.isAncestorOrSelf(struct.getCategoryPath())) {
				struct = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
			} else {
				struct = new StructureDataType(path, type.getName(), 0, dtm);
				dtm.addDataType(struct, DataTypeConflictHandler.KEEP_HANDLER);
				try {
					struct.setDescription(PLACEHOLDER_DESCRIPTION);
					struct.setCategoryPath(path);
				} catch (DuplicateNameException e) {
					Msg.error(
						ClassTypeInfoUtils.class, "Failed to change placeholder struct "
								+type.getName()+"'s CategoryPath", e);
				}
			}
		}
		if (!struct.equals(VariableUtilities.findOrCreateClassStruct(
				type.getGhidraClass(), dtm))) {
					Msg.trace(ClassTypeInfoUtils.class, "Variable Utils returned wrong class structure! "
									+ type.getName());
		}
		dtm.endTransaction(id, true);
		return (Structure) struct;
	}
	
	private static boolean isDebug(DataTypePath dtPath) {
		final String path = dtPath.toString();
		if (path.contains(".pdb") || path.contains(".xml")) {
			return true;
		}
		return dtPath.isAncestor(DWARF);
	}

    private static DataTypeManager getCppDataTypeManager(DataTypeManager dtm) {
        if (dtm instanceof ProgramBasedDataTypeManager) {
            Program program = ((ProgramBasedDataTypeManager) dtm).getProgram();
            if (GnuUtils.isGnuCompiler(program)) {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                PluginTool tool = mgr.getAnalysisTool();
                if (tool == null) {
                    // we are testing. this is irrelevant
                    return null;
                }
                return program.getDefaultPointerSize() > 4 ?
                    getDataTypeManagerByName(tool, GENERIC_CPP_LIB64) :
                    getDataTypeManagerByName(tool, GENERIC_CPP_LIB);
            }
            // TODO VisualStudio
        }
        return null;
    }

    private static DataTypeManager getDataTypeManagerByName(PluginTool tool, String name) {
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			String managerName = manager.getName();
			if (name.equals(managerName)) {
				return manager;
			}
		}
		return null;
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
            if (dtm.getDataType(struct.getDataTypePath()) != null) {
                return dtm.getPointer(dtm.getDataType(struct.getDataTypePath()));
            }
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
            struct = (Structure) dtm.resolve(struct, DataTypeConflictHandler.KEEP_HANDLER);
            return dtm.getPointer(struct, program.getDefaultPointerSize());
        } catch (DuplicateNameException e) {
            return null;
        }
    }

}