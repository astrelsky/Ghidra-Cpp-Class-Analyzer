package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class VttModel {

    public static final String SYMBOL_NAME = "VTT";
    public static final VttModel INVALID = new VttModel();

    private Program program;
    private Address address;
    private int elementCount = -1;
    private DataType dataType;
    private ClassTypeInfo typeinfo;
    private int pointerSize;
    private List<VtableModel> constructionModels = new ArrayList<VtableModel>();
    Set<Address> validAddresses;

    private VttModel() {
        this.elementCount = 0;
    }

    public VttModel(Program program, Address address) {
        this.program = program;
        this.address = address;
        this.pointerSize = program.getDefaultPointerSize();
        if (GnuUtils.isValidPointer(program, address)) {
            Address pointee = getAbsoluteAddress(program, address).subtract(pointerSize);
            if (!TypeInfoUtils.isTypeInfoPointer(program, pointee)) {
                elementCount = 0;
            } else {
                pointee =  getAbsoluteAddress(program, pointee);
                this.typeinfo = (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, pointee);
                if (!typeinfo.hasParent()) {
                    elementCount = 0;
                }
                validAddresses = new HashSet<>();
                try {
                    for (ClassTypeInfo base : typeinfo.getParentModels()) {
                        validAddresses.add(base.getAddress());
                    }
                    validAddresses.add(typeinfo.getAddress());
                } catch (InvalidDataTypeException e) {
                    Msg.error(this, "Error fething base parent models.", e);
                }
            }
        } else {
            elementCount = 0;
        }
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof VttModel)) {
            return false;
        }
        return ((VttModel) object).getAddress().equals(address);
    }

    /**
     * Gets the address of this VttModel.
     * 
     * @return the address of this VttModel.
     */
    public Address getAddress() {
        return address;
    }

    /**
     * Checks if this VttModel is valid.
     * 
     * @return true if valid.
     */
    public boolean isValid() {
        return getElementCount() != 0;
    }

    /**
     * Gets the VtableModel at the specified ordinal.
     * 
     * @param ordinal
     * @return the VtableModel at the specified ordinal.
     */
    public Vtable getVtableModel(int ordinal) {
        Address pointee = getElementPointee(ordinal);
        return pointee != null ? getVtableContaining(pointee) : VtableModel.INVALID;
    }

    /**
     * Gets the ClassTypeInfo at the specified ordinal.
     * @param ordinal
     * @return the ClassTypeInfo at the specified ordinal or null if none exists.
     */
    public ClassTypeInfo getTypeInfo(int ordinal) {
        Address pointee = getElementPointee(ordinal);
        if (pointee != null) {
            Address typeAddress = getAbsoluteAddress(program, pointee);
            return (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, typeAddress);
        }
        return null;
    }

    private Address getElementPointee(int ordinal) {
        if (ordinal >= getElementCount()) {
            return null;
        }
        Address currentAddress = address.add(ordinal * pointerSize);
        return getAbsoluteAddress(program, currentAddress).subtract(pointerSize);
    }

    private VtableModel getVtableContaining(Address a) {
        for (VtableModel vtable : constructionModels) {
            Address startAddress = vtable.getAddress();
            AddressSet set = new AddressSet(startAddress, startAddress.add(vtable.getLength()));
            if (set.contains(a)) {
                return vtable;
            }
        }
        return new VtableModel(program, a);
    }

    /**
     * Gets the construction vtable models in this VttModel.
     * 
     * @return the construction vtable models in this VttModel.
     */
    public VtableModel[] getConstructionVtableModels() {
        if (!isValid()) {
            return new VtableModel[0];
        }
        return constructionModels.toArray(new VtableModel[constructionModels.size()]);
    }

    private Address getTIAddress(Address pointerAddress) {
        try {
            Address pointer = getTIPointer(pointerAddress);
            return pointer.equals(Address.NO_ADDRESS) ? pointer
                : getAbsoluteAddress(program, pointer);
        } catch (AddressOutOfBoundsException e) {
            return null;
        }
    }

    private Address getTIPointer(Address pointerAddress) {
        Address pointer = getAbsoluteAddress(program, pointerAddress).subtract(pointerSize);
        if (!TypeInfoUtils.isTypeInfoPointer(program, pointer)) {
            return Address.NO_ADDRESS;
        } return pointer;
    }

    private int getSubTableCount(Address startAddress) {
        int i = 0;
        Address tiAddress = getTIAddress(startAddress);
        Address currentTIAddress = tiAddress;
        while (tiAddress.equals(currentTIAddress)) {
            if (!GnuUtils.isValidPointer(program, startAddress)) {
                break;
            }
            if(!validAddresses.contains(tiAddress)) {
                break;
            }
            currentTIAddress = getTIAddress(startAddress.add(++i * pointerSize));
        } return i;
    }

    private int getVTTableCount() {
        int tableSize = 0;
        Address currentAddress = address;
        ClassTypeInfo[] parentModels;
        try {
            parentModels = typeinfo.getParentModels();
        } catch (InvalidDataTypeException e) {
            return 0;
        }
        Set<ClassTypeInfo> validTypes = new HashSet<>(Arrays.asList(parentModels));
        validTypes.add(typeinfo);
        while (true) {
            if (!GnuUtils.isValidPointer(program, currentAddress)) {
                break;
            }
            Address tiAddress = getTIAddress(currentAddress);
            if (tiAddress == null) {
                break;
            } if (!validTypes.contains((TypeInfoFactory.getTypeInfo(program, tiAddress)))) {
                break;
            }
            int subCount = getSubTableCount(currentAddress);
            if(tiAddress.equals(typeinfo.getAddress())) {
                tableSize += subCount;
                currentAddress = address.add(tableSize * pointerSize);
                continue;
            }
            VtableModel cvtable = new VtableModel(program, getTIPointer(currentAddress), subCount);
            tableSize += subCount;
            currentAddress = address.add(tableSize * pointerSize);
            constructionModels.add(cvtable);
        } return tableSize;
    }
    
    /**
	 * Gets the number of elements in this VttModel.
     * 
	 * @return the number of VTable Table elements or 0 if invalid.
	 */
	public int getElementCount() {
        if (elementCount == -1) {
            elementCount = getVTTableCount();
        }
		return elementCount;
	}

    /**
     * Gets the DataType for this VttModel.
     * 
     * @return the DataType for this VttModel.
     */
    public DataType getDataType() {
        if (dataType == null) {
            DataTypeManager dtm = program.getDataTypeManager();
            PointerDataType pointerDt = new PointerDataType(dtm);
            dataType = new ArrayDataType(pointerDt, getElementCount(), pointerSize, dtm);
        }
        return dataType;
    }

}
