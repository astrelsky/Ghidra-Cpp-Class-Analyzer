package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vftable;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import static ghidra.program.model.symbol.SourceType.ANALYSIS;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;

public class ClassTypeInfoUtils {

    private static final String PLACEHOLDER_DESCRIPTION = "PlaceHolder Class Structure";
    private static final String MISSING = "Missing";
    private static final CategoryPath DWARF = new CategoryPath(CategoryPath.ROOT, "DWARF");
    private static final String SUPER = "super_";
    
    // for error logging
    private static final ClassTypeInfoUtils THIS = new ClassTypeInfoUtils();

    private ClassTypeInfoUtils() {
    }

    /**
     * Finds the Vtable for the corresponding TypeInfo.
     * 
     * @param Program     the program to be searched.
     * @param Address     the address of the TypeInfo Model's DataType.
     * @param TaskMonitor the taskmonitor to be used while searching for the vtable
     * @return The TypeInfo's Vtable Model or null if none exists
     */
    public static Vftable findVtable(Program program, Address address, TaskMonitor monitor)
        throws CancelledException {
            SymbolTable table = program.getSymbolTable();
            Listing listing = program.getListing();
            TypeInfo typeinfo = TypeInfoFactory.getTypeInfo(program, address);
            if (!(typeinfo instanceof ClassTypeInfo)) {
                return VtableModel.INVALID;
            }
            ClassTypeInfo type = (ClassTypeInfo) typeinfo;
            for (Symbol symbol : table.getChildren(typeinfo.getNamespace().getSymbol())) {
                if (symbol.getName().equals(VtableModel.SYMBOL_NAME)) {
                    VtableModel vtable = new VtableModel(program, symbol.getAddress());
                    if (vtable.isValid()) {
                        return vtable;
                    } break;
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

    private static Vftable getValidVtable(Program program, Set<Address> references,
        TaskMonitor monitor, ClassTypeInfo typeinfo) throws CancelledException {
        Listing listing = program.getListing();
        for (Address reference : references) {
            monitor.checkCanceled();
            Data data = listing.getDataContaining(reference);
            if (data != null) {
                Symbol symbol = data.getPrimarySymbol();
                if (symbol != null && !symbol.getName().equals(VtableModel.SYMBOL_NAME)) {
                    continue;
                }
            }
            VtableModel vtable = new VtableModel(program, reference, typeinfo);
            if (vtable.isValid()) {
                Function[][] functionTables = vtable.getFunctionTables();
                if (functionTables.length > 0) {
                    if (functionTables[0][0] == null) {
                        for (Function function : functionTables[0]) {
                            if (function == null) {
                                continue;
                            }
                            if (PURE_VIRTUAL_FUNCTION_NAME.equals(function.getName())) {
                                return vtable;
                            }
                        }
                        // construction vtable
                        continue;
                    }
                }
                return vtable;
            }
        }
        return VtableModel.INVALID;
    }

    /**
     * Gets the placeholder struct for a ClassTypeInfo in a specified DataTypeManager.
     * 
     * @param type
     * @param dtm
     * @return the placeholder struct for a ClassTypeInfo in a specified DataTypeManager.
     */
    public static Structure getPlaceholderStruct(ClassTypeInfo type, DataTypeManager dtm) {
        CategoryPath path = TypeInfoUtils.getDataTypePath(type).getCategoryPath();
        DataType struct = dtm.getDataType(path, type.getName());
        if (struct != null) {
            return (Structure) struct;
        }
        struct = VariableUtilities.findOrCreateClassStruct(type.getGhidraClass(), dtm);
        if (!struct.getDataTypePath().isAncestor(DWARF)) {
            struct = new StructureDataType(path, type.getName(), 0, dtm);
            dtm.addDataType(struct, DataTypeConflictHandler.KEEP_HANDLER);
            try {
                struct.setDescription(PLACEHOLDER_DESCRIPTION);
                struct.setCategoryPath(path);
            } catch (DuplicateNameException e) {
                Msg.error(
                    THIS, "Failed to change placeholder struct "+type.getName()+"'s CategoryPath", e);
            }
        }
        if (!struct.equals(VariableUtilities.findOrCreateClassStruct(type.getGhidraClass(), dtm))) {
            Msg.info(THIS, "Variable Utils returned wrong class structure!");
        }
        return (Structure) struct;
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
     * Gets the most derived parent of the ClassTypeInfo.
     * 
     * @param type
     * @return the most derived parent of the ClassTypeInfo.
     */
    public static ClassTypeInfo getPrimaryParent(ClassTypeInfo type) {
        if (type.hasParent()) {
            if (type instanceof VmiClassTypeInfoModel) {
                return ((VmiClassTypeInfoModel) type).getParentAtOffset(0, false);
            } return type.getParentModels()[0];
        } return null;
    }

    // TODO remove after resolution of issue #874 and #873
    private static void fixClassFunctionSignature(Program program, Function function, Namespace ns) {
        try {
            function.setParentNamespace(ns);
            FlatDecompilerAPI decompiler = new FlatDecompilerAPI(new FlatProgramAPI(program));
            decompiler.initialize();
            DecompInterface dInterface = decompiler.getDecompiler();
            DecompileResults results = dInterface.decompileFunction(function, 0, null);
            FunctionPrototype prototype = results.getHighFunction().getFunctionPrototype();
            List<Parameter> params = new ArrayList<>();
            Parameter returnParam = new ReturnParameterImpl(prototype.getReturnType(), program);
            // skip the this param
            for (int i = 1; i < prototype.getNumParams(); i++) {
                HighParam param = prototype.getParam(i);
                params.add(new ParameterImpl(param.getName(), param.getDataType(), program));
            }
            function.updateFunction(GenericCallingConvention.thiscall.getDeclarationName(),
                                    returnParam, params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                    true, ANALYSIS);
            decompiler.dispose();
        } catch (Exception e) {
            Msg.error(THIS, e);
        }
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
            fixClassFunctionSignature(program, function, type.getGhidraClass());
            return function;
        } catch (Exception e) {
            Msg.error(THIS, "Failed to retrieve class function at "+address, e);
            return null;
        }
    }

    /**
     * Sorts a list of classes in order of most derived.
     * @param program
     * @param classes
     */
    public static void sortByMostDerived(Program program, List<ClassTypeInfo> classes) {
        Set<ClassTypeInfo> classSet = new LinkedHashSet<>(classes);
        List<ClassTypeInfo> sortedClasses = new ArrayList<>(classes.size());
        Iterator<ClassTypeInfo> classIterator = classSet.iterator();
        while (classIterator.hasNext()) {
            ClassTypeInfo type = classIterator.next();
            ArrayDeque<ClassTypeInfo> stack = new ArrayDeque<>();
            stack.push(type);
            while(!stack.isEmpty()) {
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

    public static void inheritClass(Structure struct, Structure parent, int offset) {
        clearComponent(struct, parent.getLength(), offset);
        if (parent.getName().contains(SUPER)) {
            struct.insertAtOffset(
                offset, parent, parent.getLength(), parent.getName(), null);    
        } else {
            struct.insertAtOffset(
                offset, parent, parent.getLength(), SUPER+parent.getName(), null);
        }
        resolveStruct(struct);
    }

    protected static Structure resolveStruct(Structure struct) {
        DataTypeManager dtm = struct.getDataTypeManager();
        return (Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private static void clearComponent(Structure struct, int length, int offset) {
        for (int size = 0; size < length;) {
            if (offset >= struct.getLength()) {
                break;
            }
            DataTypeComponent comp = struct.getComponentAt(offset);
            if (comp!= null) {
                size += comp.getLength();
            } else {
                size++;
            }
            struct.deleteAtOffset(offset);
        }
    }

}