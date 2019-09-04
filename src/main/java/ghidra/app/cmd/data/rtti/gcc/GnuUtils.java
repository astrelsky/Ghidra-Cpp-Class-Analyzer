package ghidra.app.cmd.data.rtti.gcc;

import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.Collections;

import ghidra.program.model.data.DataType;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CompositeDataTypeImpl;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeComponentImpl;
import ghidra.program.model.data.ReadOnlyDataTypeComponent;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.app.util.demangler.DemanglerUtil.demangle;

public final class GnuUtils {

    private static final String PTRDIFF = "ptrdiff_t";
    private static final String PPC = "PowerPC";
    private static final String CXXABI = "__cxxabiv1";
    private static final String VPTR = "_vptr";

    public static final Set<String> COMPILER_NAMES = Set.of("gcc", "default");
    public static final String PURE_VIRTUAL_FUNCTION_NAME = "__cxa_pure_virtual";

    private static final CategoryPath CXXABI_PATH = new CategoryPath(CategoryPath.ROOT, CXXABI);

    private GnuUtils() {
    }

    /**
     * Create a new DataTypeComponent for a CompositeDataType or DynamicDataType.
     * 
     * @param DataType          The new components DataType.
     * @param DynamicDataType   The DataType this component will be added to.
     * @param DataTypeComponent The previously added datatype component.
     * @param String            The field name for the component.
     * @param String            The comment for the component.
     * @return the new ReadOnlyDataTypeComponent.
     */
    public static DataTypeComponent getComponent(DataType dataType, DataType child, DataTypeComponent previous,
            String name, String comment) {
        return getComponent(dataType, child, previous, name, comment, 0);
    }

    protected static DataTypeComponent getComponent(DataType dataType, DataType child,
        DataTypeComponent previous, String name, String comment, int offset) {
            if (previous == null)
                return getComponent(dataType, child, name, comment);
            if (child instanceof DynamicDataType) {
                return new ReadOnlyDataTypeComponent(
                    dataType, (DynamicDataType) child, dataType.getLength(),
                    previous.getOrdinal() + 1, previous.getEndOffset() + 1 + offset,
                    name, comment);
            } else if (child instanceof CompositeDataTypeImpl) {
                return new DataTypeComponentImpl(
                    dataType, (CompositeDataTypeImpl) child, dataType.getLength(),
                    previous.getOrdinal() + 1, previous.getEndOffset() + 1 + offset,
                    name, comment);
            }
            return null;
    }

    /**
     * Create a new DataTypeComponent for a CompositeDataType or DynamicDataType.
     * 
     * @param DataType        The new components DataType.
     * @param DynamicDataType The DataType this component will be added to.
     * @param String          The field name for the component.
     * @param String          The comment for the component.
     * @return the new ReadOnlyDataTypeComponent.
     */
    public static DataTypeComponent getComponent(DataType dataType, DataType child,
        String name, String comment) {
            if (child instanceof DynamicDataType) {
                return new ReadOnlyDataTypeComponent(
                    dataType, (DynamicDataType) child, dataType.getLength(), 0, 0, name,comment);
            } else if (child instanceof CompositeDataTypeImpl) {
                return new DataTypeComponentImpl(
                    dataType, (CompositeDataTypeImpl) child, dataType.getLength(), 0, 0,
                    name, comment);
            }
            return null;
    }

    /**
     * Gets the __cxxabiv1 CategoryPath.
     * 
     * @return the __cxxabiv1 CategoryPath.
     */
    public static CategoryPath getCxxAbiCategoryPath() {
        return CXXABI_PATH;
    }

    /**
     * @param DataTypeManager the programs datatype manager.
     * @return true if LLP64 was defined
     */
    public static boolean isLLP64(DataTypeManager dtm) {
        return dtm.getDataOrganization().getPointerSize() == 8;
    }

    private static DataType createPtrDiff(DataTypeManager dtm) {
        DataType dataType = isLLP64(dtm) ? LongLongDataType.dataType : IntegerDataType.dataType;
        return new TypedefDataType(CategoryPath.ROOT, PTRDIFF, dataType, dtm);
    }

    private static DataType createVptr() {
        FunctionDefinitionDataType dataType = new FunctionDefinitionDataType(CXXABI_PATH, VPTR);
        // According to results from virtual classes with DWARF information
        dataType.setReturnType(IntegerDataType.dataType);
        dataType.setVarArgs(true);
        return dataType;
    }

    /**
     * Gets a generic _vptr DataType.
     * 
     * @param DataTypeManager the programs datatype manager.
     * @return A generic _vptr DataType.
     */
    public static DataType getVptr(DataTypeManager dtm) {
        // TODO figure out how to actually make it work correctly
        //return dtm.getPointer(VoidDataType.dataType);
        
        DataType _vptr = createVptr();
        if (dtm.contains(_vptr)) {
            return dtm.getPointer(dtm.resolve(_vptr, KEEP_HANDLER));
        }
        return dtm.getPointer(_vptr);
    }

    /**
     * Gets the appropriate TypeDefDataType for the builtin __PTRDIFF_TYPE__
     * 
     * @param DataTypeManager the programs datatype manager.
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
     * 
     * @param DataTypeManager the programs datatype manager.
     * @return the size in bytes of __PTRDIFF_TYPE__
     */
    public static int getPtrDiffSize(DataTypeManager dtm) {
        return getPtrDiff_t(dtm).getLength();
    }

    /**
     * Gets all MemoryBlocks in a Program which hold non-volatile data.
     * @param Program the program to be searched.
     * @return A list of all memory blocks with non-volatile data.
     */
    public static List<MemoryBlock> getAllDataBlocks(Program program) {
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        List<MemoryBlock> dataBlocks = new ArrayList<MemoryBlock>();
        for (MemoryBlock block : blocks) {
            if (isDataBlock(block)) {
                // READ | WRITE && !EXECUTE && !VOLATILE
                dataBlocks.add(block);
            }
        }
        return dataBlocks;
    }

    /**
     * Returns true if this MemoryBlock has non-volatile data.
     * 
     * @param MemoryBlock
     * @return true if this MemoryBlock has non-volatile data.
     */
    public static boolean isDataBlock(MemoryBlock block) {
        return block.isRead() || block.isWrite();
    }

    /**
     * Checks if a Program's language is PowerPC64.
     * 
     * @param program
     * @return true if the program's language is PowerPC64.
     */
    public static boolean hasFunctionDescriptors(Program program) {
        Processor processor = program.getLanguage().getProcessor();
        if (!processor.toString().contentEquals(PPC)) {
            return false;
        } return isLLP64(program.getDataTypeManager());
    }

    /**
     * Checks if a function pointer is located at the specified address.
     * 
     * @param program
     * @param address
     * @return true if a function pointer is located at the specified address.
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
     * Checks if a null pointer is located at the specified address.
     * 
     * @param program
     * @param address
     * @return true if a null pointer is located at the specified address.
     */
    public static boolean isNullPointer(Program program, Address address) {
        return isNullPointer(new MemoryBufferImpl(program.getMemory(), address));
    }

    /**
     * Checks if a null pointer is located at the specified address.
     * 
     * @param buf
     * @return true if a null pointer is located at the specified address.
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
     * Checks if a valid pointer is located at the specified address.
     * 
     * @param program
     * @param address
     * @return true if a valid pointer is located at the specified address.
     */
    public static boolean isValidPointer(Program program, Address address) {
        Address pointee = getAbsoluteAddress(program, address);
        if (pointee != null) {
            return program.getMemory().getLoadedAndInitializedAddressSet().contains(pointee);
        } return false;
    }

    /**
     * Checks if a valid pointer is located at the specified address.
     * 
     * @param buf
     * @return true if a valid pointer is located at the specified address.
     */
    public static boolean isValidPointer(MemBuffer buf) {
        return buf != null ?
            isValidPointer(buf.getMemory().getProgram(), buf.getAddress()) : false;
    }

    /**
     * Gets all direct data references to the specified address.
     * 
     * @param program
     * @param address
     * @return a set of all direct data references to the specified address.
     */
    public static Set<Address> getDirectDataReferences(Program program, Address address) {
        try {
            return getDirectDataReferences(program, address, new DummyCancellableTaskMonitor());
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Gets all direct data references to the specified address.
     * @param program
     * @param dataAddress
     * @param monitor
     * @return a set of all direct data references to the specified address.
     * @throws CancelledException
     */
    public static Set<Address> getDirectDataReferences(Program program, Address dataAddress,
        TaskMonitor monitor) throws CancelledException {
            if (dataAddress == null)
                return Collections.emptySet();
            List<MemoryBlock> dataBlocks = getAllDataBlocks(program);
            int pointerAlignment =
                program.getDataTypeManager().getDataOrganization().getDefaultPointerAlignment();
            return ProgramMemoryUtil.findDirectReferences(program, dataBlocks,
                pointerAlignment, dataAddress, monitor);
    }

}
