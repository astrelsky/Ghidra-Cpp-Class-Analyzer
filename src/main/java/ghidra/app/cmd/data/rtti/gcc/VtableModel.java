package ghidra.app.cmd.data.rtti.gcc;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.app.cmd.data.rtti.gcc.vtable.VtableDataType;
import ghidra.app.cmd.data.rtti.gcc.vtable.VtablePrefixDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

/**
 * Model for GNU Vtables
 */
public class VtableModel implements Vtable {

    public static final String SYMBOL_NAME = "vtable";
    public static final String CONSTRUCTION_SYMBOL_NAME = "construction-"+SYMBOL_NAME;
    public static final String DESCRIPTION = "Vtable Model";
    public static final String MANGLED_PREFIX = "_ZTV";

    private MemoryBufferImpl buf;

    private Program program;
    private boolean isValid = true;
    private VtableDataType dataType = VtableDataType.dataType;
    private Address address;
    private int tableOrdinal = 2;
    private int ptrDiffSize;
    private Set<Function> functions = new HashSet<>();
    private ClassTypeInfo type = null;
    private long[] offsets;

    public static final VtableModel NO_VTABLE = new VtableModel();

    private VtableModel() {
        isValid = false;
    }

    public VtableModel(Program program, Address address, ClassTypeInfo type) {
        this(program, address);
        this.type = type;
    }

    public VtableModel(Program program, Address address, int elementCount) {
        this(program, address);
        if (isValid) {
            this.dataType = new VtableDataType(program.getDataTypeManager(), this, elementCount);
        }
    }
    
    /**
     * Constructs a new VtableModel
     * 
     * @param Program program the vtable is in.
     * @param Address starting address of the vtable or the first typeinfo pointer.
     */
    public VtableModel(Program program, Address address) {
        this.program = program;
        this.address = address;
        boolean isTypeInfoPointer = TypeInfoUtils.isTypeInfoPointer(program, address);
        DataTypeManager dtm = program.getDataTypeManager();
        DataType ptrdiff_t = GnuUtils.getPtrDiff_t(dtm);
        this.buf = new MemoryBufferImpl(program.getMemory(), address);
        ptrDiffSize = ptrdiff_t.getLength();
        int length = VtableUtils.getNumPtrDiffs(buf);
        if (length == 0) {
            isValid = false;
        } else {
            if (!isTypeInfoPointer) {
                this.address = address;
            } else {
                this.address = address.subtract(length * ptrDiffSize);
            }
            if (isValid) {
                buf.setPosition(this.address);
                this.dataType = new VtableDataType(dtm, this);
            }
        }
    }

    @Override
    public ClassTypeInfo getTypeInfo() throws InvalidDataTypeException {
        validate();
        if (type == null) {
            type = VtableUtils.getTypeInfo(program, address);
        }
        return type;
    }

    @Override
    
    public void validate() throws InvalidDataTypeException {
        if (!isValid) {
            if (address != null) {
                throw new InvalidDataTypeException(
                    "Vtable at "+address.toString()+" is not valid.");
            } throw new InvalidDataTypeException(
                "Invalid Vtable.");
        }
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof VtableModel)) {
            return false;
        }
        return isValid ? ((VtableModel) object).getAddress().equals(address) : false;
    }

    /**
     * Gets the corrected start address of the vtable.
     * 
     * @return the correct start address or NO_ADDRESS if invalid.
     */
    public Address getAddress() {
        return address;
    }

    private void resetBuffer() {
        buf.setPosition(address);
    }

    public DataType getDataType() throws InvalidDataTypeException {
        validate();
        return dataType;
    }

    @Override
    public Address[] getTableAddresses() throws InvalidDataTypeException {
        resetBuffer();
        if (VtablePrefixDataType.dataType.getNumComponents(buf) <= tableOrdinal) {
            return new Address[0];
        }
        DataTypeComponent[] comps = dataType.getComponents(buf);
        Address[] addresses = new Address[comps.length];
        for (int i = 0; i < comps.length; i++) {
            int offset = VtablePrefixDataType.dataType.getComponent(tableOrdinal, buf).getOffset();
            addresses[i] = buf.getAddress().add(offset);
            try {
                buf.advance(comps[i].getLength());
            } catch (AddressOverflowException e) {
                return addresses;
            }
        }
        return addresses;
    }

    private Function createFunction(Address currentAddress) {
        Listing listing = program.getListing();
        if (listing.getInstructionAt(currentAddress) == null) {
            // If it has not been disassembled, disassemble it first.
            if (program.getMemory().getBlock(currentAddress).isInitialized()) {
                DisassembleCommand cmd = new DisassembleCommand(currentAddress, null, true);
                cmd.applyTo(program);
            }
        }
        CreateFunctionCmd cmd = new CreateFunctionCmd(currentAddress);
        cmd.applyTo(program);
        return cmd.getFunction();
    }

    private Address getFunctionAddress(Address currentAddress) {
        Address functionAddress = getAbsoluteAddress(program, currentAddress);
        if (GnuUtils.hasFunctionDescriptors(program) && functionAddress.getOffset() != 0) {
            Relocation reloc = program.getRelocationTable().getRelocation(currentAddress);
            if (reloc == null || reloc.getSymbolName() == null) {
                return getAbsoluteAddress(program, functionAddress);
            }
        } return functionAddress;
    }

    @Override
    
    public Function[][] getFunctionTables() throws InvalidDataTypeException {
        validate();
        int pointerSize = program.getDefaultPointerSize();
        Address[] tableAddresses = getTableAddresses();
        if (tableAddresses.length == 0) {
            return new Function[0][];
        }
        Function[][] result = new Function[tableAddresses.length][];
        Listing listing = program.getListing();
        for (int i = 0; i < tableAddresses.length; i++) {
            Address currentAddress = tableAddresses[i];
            int elements = VtableUtils.getFunctionTableLength(program, currentAddress);
            Function[] virtualFunctions = new Function[elements];
            for (int j = 0; j < elements; j++) {
                Address functionAddress = getFunctionAddress(currentAddress);
                if (functionAddress.getOffset() != 0) {
                    Function function = listing.getFunctionAt(functionAddress);
                    if (function == null) {
                        function = createFunction(functionAddress);
                    }
                    functions.add(function);
                    virtualFunctions[j] = function;
                } else {
                    virtualFunctions[j] = null;
                }
                currentAddress = currentAddress.add(pointerSize);
            } result[i] = virtualFunctions;
        } return result;
    }

    @Override
    
    public boolean containsFunction(Function function) throws InvalidDataTypeException {
        if (functions.isEmpty()) {
            getFunctionTables();
        } return functions.contains(function);
    }

    /**
     * @see ghidra.program.model.data.DataType#getLength()
     * @return
     */
    public int getLength() {
        if (!isValid) {
            return 0;
        }
        resetBuffer();
        return dataType.getLength(buf, 0);
    }
    
    /**
     * Gets the ptrdiff_t value within the offset array.
     * 
     * @param ordinal the offset ordinal.
     * @return the offset value.
     * @throws InvalidDataTypeException 
     */
    public long getOffset(int ordinal) throws InvalidDataTypeException {
        validate();
        if (ordinal >= getElementCount()) {
            return Long.MAX_VALUE;
        }
        resetBuffer();
        return dataType.getOffsetToVirtualBase(buf, ordinal);
    }

    /**
     * Gets the whole ptrdiff_t array.
     * 
     * @return the whole ptrdiff_t array.
     * @throws InvalidDataTypeException
     */
    public long[] getOffsetArray() throws InvalidDataTypeException {
        if (offsets == null) {
            offsets = doGetOffsetArray();
        }
        return offsets;
    }

    private long[] doGetOffsetArray() throws InvalidDataTypeException {
        validate();
        resetBuffer();
        DataTypeComponent comp = dataType.getComponents(buf)[0];
        buf.setPosition(address.add(comp.getOffset()));
        comp = VtablePrefixDataType.dataType.getComponent(0, buf);
        Array offsetArray = (Array) comp.getDataType();
        int length = offsetArray.getElementLength();
        long[] result = new long[offsetArray.getNumElements()];
        try {
            for (int i = 0; i < result.length; i++) {
                result[i] = buf.getBigInteger(i * length, length, true).longValue();
            }
        } catch (MemoryAccessException e) {
            return new long[0];
        } return result;
    }

    /**
     * Gets the number of vtable_prefix's in this vtable.
     * 
     * @return the number of vtable_prefix's in this vtable.
     * @throws InvalidDataTypeException 
     */
    public int getElementCount() throws InvalidDataTypeException {
        validate();
        resetBuffer();
        return dataType.getNumComponents(buf);
    }
}