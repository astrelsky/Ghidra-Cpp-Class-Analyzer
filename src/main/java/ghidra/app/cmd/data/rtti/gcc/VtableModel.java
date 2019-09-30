package ghidra.app.cmd.data.rtti.gcc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;

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
    private Address address;
    private static final int FUNCTION_TABLE_ORDINAL = 2;
    private static final int MAX_PREFIX_ELEMENTS = 3;
    private int arrayCount;
    private boolean construction;
    private Set<Function> functions = new HashSet<>();
    private ClassTypeInfo type = null;
    private long[] offsets;
    private List<VtablePrefixModel> vtablePrefixes;

    public static final VtableModel NO_VTABLE = new VtableModel();

    private VtableModel() {
        isValid = false;
    }

    public VtableModel(Program program, Address address, ClassTypeInfo type) {
        this(program, address, type, -1, false);
    }

    public VtableModel(Program program, Address address) {
        this(program, address, null, -1, false);
    }
    
    /**
     * Constructs a new VtableModel
     * 
     * @param Program program the vtable is in.
     * @param Address starting address of the vtable or the first typeinfo pointer.
     */
    public VtableModel(Program program, Address address, ClassTypeInfo type, int arrayCount, boolean construction) {
        this.program = program;
        this.address = address;
        this.type = type;
        this.arrayCount = arrayCount;
        this.construction = construction;
        if (TypeInfoUtils.isTypeInfoPointer(program, address)) {
            if (this.type == null) {
                Address typeAddress = getAbsoluteAddress(program, address);
                this.type = (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, typeAddress);
            }
        } else if (this.type == null) {
            int length = VtableUtils.getNumPtrDiffs(program, address);
            DataType ptrdiff_t = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
            Address typePointerAddress = address.add(length * ptrdiff_t.getLength());
            Address typeAddress = getAbsoluteAddress(program, typePointerAddress);
            this.type = (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, typeAddress);
        }
        try {
            setupVtablePrefixes();
            this.isValid = !vtablePrefixes.isEmpty();
        } catch (InvalidDataTypeException e) {
            this.isValid = false;
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

    @Override
    public Address[] getTableAddresses() throws InvalidDataTypeException {
        validate();
        Address[] result = new Address[vtablePrefixes.size()];
        for (int i = 0; i < result.length; i++) {
            try {
                result[i] = vtablePrefixes.get(i).getTableAddress();
            } catch (IndexOutOfBoundsException e) {
                result = Arrays.copyOf(result, i);
                break;
            }
        }
        return result;
    }

    @Override
    
    public Function[][] getFunctionTables() throws InvalidDataTypeException {
        validate();
        Address[] tableAddresses = getTableAddresses();
        if (tableAddresses.length == 0) {
            return new Function[0][];
        }
        Function[][] result = new Function[tableAddresses.length][];
        for (int i = 0; i < tableAddresses.length; i++) {
            result[i] = VtableUtils.getFunctionTable(program, tableAddresses[i]);
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
        int size = 0;
        for (VtablePrefixModel prefix : vtablePrefixes) {
            size += prefix.getPrefixSize();
        }
        return size;
    }
    
    /**
     * Gets the ptrdiff_t value within the base offset array.
     * 
     * @param index the index in the vtable_prefix array.
     * @param ordinal the offset ordinal.
     * @return the offset value.
     * @throws InvalidDataTypeException 
     */
    public long getOffset(int index, int ordinal) throws InvalidDataTypeException {
        validate();
        if (ordinal >= getElementCount()) {
            return Long.MAX_VALUE;
        }
        resetBuffer();
        return vtablePrefixes.get(index).getBaseOffset(ordinal);
    }

    /**
     * Gets the whole ptrdiff_t array.
     * 
     * @return the whole ptrdiff_t array.
     * @throws InvalidDataTypeException
     */
    public long[] getBaseOffsetArray() throws InvalidDataTypeException {
        validate();
        if (offsets == null) {
            offsets = vtablePrefixes.get(0).getBaseOffsets();
        }
        return offsets;
    }

    /**
     * Gets the number of vtable_prefix's in this vtable.
     * 
     * @return the number of vtable_prefix's in this vtable.
     * @throws InvalidDataTypeException 
     */
    public int getElementCount() throws InvalidDataTypeException {
        validate();
        return vtablePrefixes.size();
    }

    private Address getNextPrefixAddress() {
        int size = 0;
        for (VtablePrefixModel prefix : vtablePrefixes) {
            size += prefix.getPrefixSize();
        }
        return address.add(size);
    }

    public List<DataType> getDataTypes() {
        List<DataType> result = new ArrayList<>(vtablePrefixes.size() * MAX_PREFIX_ELEMENTS);
        for (VtablePrefixModel prefix : vtablePrefixes) {
            result.addAll(prefix.dataTypes);
        }
        return result;
    }

    private void setupVtablePrefixes() throws InvalidDataTypeException {
        vtablePrefixes = new ArrayList<>();
        int count = construction ? 2 : type.getVirtualParents().size()+1;
        VtablePrefixModel prefix = new VtablePrefixModel(getNextPrefixAddress(), count);
        if (!prefix.isValid()) {
            return;
        }
        if (TypeInfoUtils.isTypeInfoPointer(program, address)) {
            address = prefix.prefixAddress;
        }
        if (arrayCount < 0) {
            while (prefix.isValid()) {
                vtablePrefixes.add(prefix);
                prefix = new VtablePrefixModel(getNextPrefixAddress());
            }
        } else {
            vtablePrefixes.add(prefix);
            for (int i = 1; i < arrayCount; i++) {
                prefix = new VtablePrefixModel(getNextPrefixAddress());
                if (!prefix.isValid()) {
                    break;
                }
                vtablePrefixes.add(prefix);
            }
        }
    }

    public List<VtablePrefixModel> getVtablePrefixes() {
        return vtablePrefixes;
    }

    private class VtablePrefixModel {

        private Address prefixAddress;
        private List<DataType> dataTypes;

        private VtablePrefixModel(Address prefixAddress) {
            this(prefixAddress, -1);
        }

        private VtablePrefixModel(Address prefixAddress, int ptrDiffs) {
            this.prefixAddress = prefixAddress;
            int numPtrDiffs = ptrDiffs > 0 ? ptrDiffs :
                VtableUtils.getNumPtrDiffs(program, prefixAddress);
            dataTypes = new ArrayList<>(3);
            if (numPtrDiffs > 0) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType ptrdiff_t = GnuUtils.getPtrDiff_t(dtm);
                int pointerSize = program.getDefaultPointerSize();
                if (TypeInfoUtils.isTypeInfoPointer(program, prefixAddress)) {
                    this.prefixAddress = prefixAddress.subtract(numPtrDiffs * ptrdiff_t.getLength());
                }
                dataTypes.add(new ArrayDataType(ptrdiff_t, numPtrDiffs, ptrdiff_t.getLength()));
                dataTypes.add(new PointerDataType(null, pointerSize, dtm));
                Address tableAddress = this.prefixAddress.add(getPrefixSize());
                int tableSize = VtableUtils.getFunctionTableLength(program, tableAddress);
                if (tableSize > 0) {
                    ArrayDataType table = new ArrayDataType(
                        PointerDataType.dataType, tableSize, pointerSize, dtm);
                    dataTypes.add(table);
                }
            }
        }

        private boolean isValid() {
            if (dataTypes.size() > 1) {
                int offset = dataTypes.get(0).getLength();
                Address pointee = getAbsoluteAddress(
                    program, prefixAddress.add(offset));
                if (pointee != null) {
                    return pointee.equals(type.getAddress());
                }
            }
            return false;
        }

        private int getPrefixSize() {
            int size = 0;
            for (DataType dt : dataTypes) {
                size += dt.getLength();
            }
            return size;
        }

        private Address getTableAddress() {
            int size = 0;
            for (int i = 0; i < FUNCTION_TABLE_ORDINAL; i++) {
                size += dataTypes.get(i).getLength();
            }
            return prefixAddress.add(size);
        }

        private long[] getBaseOffsets() {
            try {
                Array array = (Array) dataTypes.get(0);
                MemoryBufferImpl prefixBuf = new MemoryBufferImpl(
                    program.getMemory(), prefixAddress);
                int length = array.getElementLength();
                long[] result = new long[array.getNumElements()];
                for (int i = 0; i < result.length; i++) {
                    result[i] = prefixBuf.getBigInteger(i*length, length, true).longValue();
                }
                return result;
            } catch (MemoryAccessException e) {
                Msg.error(this, "Failed to retreive base offsets at "+prefixAddress, e);
                return new long[0];
            }
        }

        private long getBaseOffset(int ordinal) {
            Array array = (Array) dataTypes.get(0);
            if (ordinal >= array.getElementLength()) {
                return -1;
            }
            return getBaseOffsets()[ordinal];
        }
    }
}