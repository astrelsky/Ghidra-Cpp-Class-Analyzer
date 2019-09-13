package ghidra.app.cmd.data.rtti.gcc;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class VtableUtils {

    // that's still a awful lot
    public static final int MAX_PTR_DIFFS = 25;

    @SuppressWarnings("unused")
    private static final VtableUtils THIS = new VtableUtils();
    private VtableUtils() {}

    @FunctionalInterface
    private interface IntToLongFunction {
        long applyAsLong(int value) throws MemoryAccessException;
    }

    /**
     * Gets the number of ptrdiff_t's in the vtable_prefix at the address.
     * 
     * @param Program
     * @param Address
     * @return the number of ptrdiff_t's in the vtable_prefix at the address.
     */
    public static int getNumPtrDiffs(Program program, Address address) {
        return getNumPtrDiffs(program, address, MAX_PTR_DIFFS);
    }

    /* This is not pretty. The rules I have found are as follows.
       Positive values may only repeate when going down.
       Negative values and 0 may repeate.
       Values may not go from negative/positive and then back or vise-versa.
       AddressOverflowException and MemoryAccessException may only occur when
       counting upwards from the typeinfo pointer.
       Most classes within libstdc++ contain no more than 2 ptrdiff_t's,
       however this was written to be able to withstand large inheritance chains. */
    /**
     * Gets the size of the ptrdiff_t array at the start of a vtable_prefix.
     * 
     * @param buffer
     * @param maxLength
     * @return the number of ptrdiff_t's in the array or 0 if invalid.
     */
    public static int getNumPtrDiffs(Program program, Address address, int maxLength) {
        Listing listing = program.getListing();
        Data before = listing.getDefinedDataBefore(address);
        Data after = listing.getDefinedDataAfter(address);
        Data containing = listing.getDefinedDataContaining(address);
        if (isValidData(containing)) {
            AddressRangeImpl set;
            if (before.equals(containing)) {
                set = new AddressRangeImpl(before.getAddress(), after.getAddress());
            } else {
                set = new AddressRangeImpl(before.getMaxAddress(), after.getAddress());
            }
            if (TypeInfoUtils.isTypeInfoPointer(program, address)) {
                if (isPtrDiffArray(before)) {
                    return before.getNumComponents();
                }
                if (isVptrArray(after)) {
                    after = listing.getDefinedDataAfter(after.getMaxAddress());
                }
                int ptrDiffSize = GnuUtils.getPtrDiffSize(program.getDataTypeManager());
                set = new AddressRangeImpl(before.getMaxAddress(), after.getAddress());
                return getNumPtrDiffs(program, address.subtract(ptrDiffSize), set, true);
            }
            return getNumPtrDiffs(program, address, set, false);
        }
        return 0;
    }

    private static boolean isPtrDiffArray(Data data) {
        if (data != null && data.isArray()) {
            DataType ptrDiff = GnuUtils.getPtrDiff_t(data.getDataType().getDataTypeManager());
            return ((Array) data.getDataType()).getDataType().equals(ptrDiff);
        }
        return false;
    }

    private static boolean isVptrArray(Data data) {
        if (data != null && data.isArray()) {
            return ((Array) data.getDataType()).getDataType().equals(PointerDataType.dataType);
        }
        return false;
    }

    private static int getNumPtrDiffs(Program program, Address address,
        AddressRange range, boolean reverse) {
            MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), address);
            DataType ptrdiff_t = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
            int length = ptrdiff_t.getLength();
            int direction = reverse? -1 : 1;
            int count = 0;
            long value = 0;
            List<Long> values = new ArrayList<>();
            IntToLongFunction getValue = length == 8 ? buf::getLong : buf::getInt;
            while (range.contains(buf.getAddress())) {
                try {
                    if (GnuUtils.isValidPointer(buf) && !(getValue.applyAsLong(0) == 0)) {
                        if ((direction < 0) ^ TypeInfoUtils.isTypeInfoPointer(buf)) {
                            break;
                        } else if (direction < 0) {
                            break;
                        } return 0;
                    }
                    value = getValue.applyAsLong(0);
                    if (value < 0 && direction < 0) {
                        return count;
                    }
                    if (value > 0 && direction < 0) {
                        if (values.contains(value)) {
                            return 0;
                        } values.add(value);
                    }
                    count++;
                    buf.advance(direction * length);
                } catch (MemoryAccessException | AddressOverflowException e) {
                    if (direction < 0) {
                        return count;
                    } return 0;
                }
            }
            return count;
    }

    private static boolean isValidData(Data data) {
        if (data == null) {
            return true;
        }
        if (data.isPointer()) {
            return TypeInfoUtils.isTypeInfoPointer(data);
        }
        if (Undefined.isUndefined(data.getDataType())) {
            return true;
        }
        if (!data.isArray()) {
            return data.getDataType() instanceof DefaultDataType;
        }
        if (Undefined.isUndefinedArray(data.getDataType())) {
            return true;
        }
        DataType ptrDiff = GnuUtils.getPtrDiff_t(data.getDataType().getDataTypeManager());
        return ((Array) data.getDataType()).getDataType().equals(ptrDiff);
    }

    /**
     * Returns the TypeInfo Model this vtable points to.
     * 
     * @param program program the vtable is in.
     * @param address address of the start of the vtable.
     * @return the pointed to TypeInfo Model or null if none found.
     */
    public static ClassTypeInfo getTypeInfo(Program program, Address address) {
        DataTypeManager dtm = program.getDataTypeManager();
        int ptrDiffSize = GnuUtils.getPtrDiffSize(dtm);
        int numPtrDiffs = getNumPtrDiffs(program, address);
        Address currentAddress = address.add(ptrDiffSize * numPtrDiffs);
        if (TypeInfoUtils.isTypeInfoPointer(program, currentAddress)) {
            return (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, getAbsoluteAddress(program, currentAddress));
        }
        return null;
    }

    /**
     * Gets the number of elements in the vtable_prefix's function table.
     * 
     * @param program
     * @param address
     * @return the number of elements in the vtable_prefix's function table.
     */
    public static int getFunctionTableLength(Program program, Address address) {
        int tableSize = 0;
        MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), address);
        int pointerSize = program.getDefaultPointerSize();
        while (GnuUtils.isNullPointer(buf)) {
            tableSize++;
            try {
                buf.advance(pointerSize);
            }
            catch (AddressOverflowException e) {
                return 0;
            }
        }
        while (GnuUtils.isFunctionPointer(program, buf.getAddress())) {
            tableSize++;
            try {
                buf.advance(pointerSize);
            }
            catch (AddressOverflowException e) {
                // Assume table ends at end of address set
                break;
            }
        }
        if (TypeInfoUtils.isTypeInfoPointer(program, buf.getAddress())) {
            if (GnuUtils.isNullPointer(program, buf.getAddress().subtract(pointerSize))) {
                // Prevent colliding with another vtable prefix
                tableSize--;
            }
        }
        return tableSize;
    }

    /**
     * Gets the VttModel for the specified VtableModel if one exists.
     * 
     * @param program
     * @param vtable
     * @return the VttModel or invalid if none.
     * @throws InvalidDataTypeException
     */
    public static VttModel getVttModel(Program program, VtableModel vtable)
        throws InvalidDataTypeException {
            if (vtable.getTypeInfo().getTypeName().contains(TypeInfoModel.STRUCTURE_NAME)) {
                return VttModel.INVALID;
            }
            Address[] tableAddresses = vtable.getTableAddresses();
            if (tableAddresses.length == 0) {
                return VttModel.INVALID;
            }
            Set<Address> references = GnuUtils.getDirectDataReferences(program, tableAddresses[0]);
            if (references.isEmpty()) {
                return VttModel.INVALID;
            }
            // VTT typically follows the vtable
            Address address = vtable.getAddress().add(vtable.getLength());
            if (references.contains(address)) {
                VttModel vtt = new VttModel(program, address);
                if (vtt.isValid()) {
                    return vtt;
                }
            }
            Iterator<Address> refIterator = references.iterator();
            while (refIterator.hasNext()) {
                VttModel vtt = new VttModel(program, refIterator.next());
                if (vtt.isValid()) {
                    return vtt;
                }
            }
            return VttModel.INVALID;
    }
}