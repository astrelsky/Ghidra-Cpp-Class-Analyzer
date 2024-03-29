package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class VttModel {

	public static final String SYMBOL_NAME = "VTT";
	public static final VttModel INVALID = new VttModel();

	private final Address address;
	private int elementCount = -1;
	private DataType dataType;
	private ClassTypeInfo typeinfo;
	private int pointerSize;
	private List<GnuVtable> constructionModels;
	private final ProgramClassTypeInfoManager manager;
	private Set<Address> validAddresses;

	private VttModel() {
		this.elementCount = 0;
		this.address = null;
		this.manager = null;
	}

	/**
	 * Constructs a new VttModel
	 * @param program the program containing the VttModel
	 * @param address the address of the VttModel
	 */
	public VttModel(Program program, Address address) {
		this.manager = CppClassAnalyzerUtils.getManager(program);
		this.address = address;
		this.pointerSize = program.getDefaultPointerSize();
		if (GnuUtils.isValidPointer(program, address)) {
			Address pointee = getAbsoluteAddress(program, address).subtract(pointerSize);
			if (!TypeInfoUtils.isTypeInfoPointer(program, pointee)) {
				elementCount = 0;
			} else {
				pointee =  getAbsoluteAddress(program, pointee);
				this.typeinfo = manager.getType(pointee);
				if (!typeinfo.hasParent()) {
					elementCount = 0;
				}
				validAddresses = new HashSet<>();
				for (ClassTypeInfo base : typeinfo.getParentModels()) {
					validAddresses.add(base.getAddress());
				}
				validAddresses.add(typeinfo.getAddress());
			}
		} else {
			elementCount = 0;
		}
	}

	private Program getProgram() {
		return manager.getProgram();
	}

	@Override
	public int hashCode() {
		if (isValid()) {
			return getAddress().hashCode();
		}
		return super.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (!(object instanceof VttModel)) {
			return false;
		}
		return ((VttModel) object).getAddress().equals(address);
	}

	/**
	 * Gets the address of this VttModel
	 * @return the address of this VttModel
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Checks if this VttModel is valid
	 * @return true if valid
	 */
	public boolean isValid() {
		int count = getElementCount();
		return count > 0;
	}

	/**
	 * Gets the Vtable at the specified ordinal
	 * @param ordinal the ordinal of the Vtable
	 * @return the Vtable at the specified ordinal
	 */
	public Vtable getVtableModel(int ordinal) {
		Address pointee = getElementPointee(ordinal);
		return pointee != null ? getVtableContaining(pointee) : GnuVtable.NO_VTABLE;
	}

	/**
	 * Gets the ClassTypeInfo at the specified ordinal
	 * @param ordinal the ordinal of the Vtable containing the ClassTypeInfo pointer
	 * @return the ClassTypeInfo at the specified ordinal or null if none exists
	 * @see Vtable#getTypeInfo()
	 */
	public ClassTypeInfo getTypeInfo(int ordinal) {
		Address pointee = getElementPointee(ordinal);
		if (pointee != null) {
			Address typeAddress = getAbsoluteAddress(getProgram(), pointee);
			return manager.getType(typeAddress);
		}
		return null;
	}

	private Address getElementPointee(int ordinal) {
		if (ordinal >= getElementCount()) {
			return null;
		}
		Address currentAddress = address.add(ordinal * pointerSize);
		return getAbsoluteAddress(getProgram(), currentAddress).subtract(pointerSize);
	}

	private static boolean vtableContainsAddress(GnuVtable vtable, Address a) {
		Address startAddress = vtable.getAddress();
		AddressSet set = new AddressSet(startAddress, startAddress.add(vtable.getLength()));
		return set.contains(a);
	}

	private GnuVtable getVtableContaining(Address a) {
		for (GnuVtable vtable : constructionModels) {
			if (vtableContainsAddress(vtable, a)) {
				return vtable;
			}
		}
		GnuVtable vtable = (GnuVtable) typeinfo.getVtable();
		if (vtableContainsAddress(vtable, a)) {
			return vtable;
		}
		return null;
	}

	/**
	 * Gets the construction vtable models in this VttModel
	 * @return the construction vtable models in this VttModel
	 */
	public GnuVtable[] getConstructionVtableModels() {
		if (!isValid()) {
			return new GnuVtable[0];
		}
		return constructionModels.toArray(new GnuVtable[constructionModels.size()]);
	}

	private Address getTIAddress(Address pointerAddress) {
		try {
			Address pointer = getTIPointer(pointerAddress);
			return pointer.equals(Address.NO_ADDRESS) ? pointer
				: getAbsoluteAddress(getProgram(), pointer);
		} catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private Address getTIPointer(Address pointerAddress) {
		Program program = getProgram();
		Address pointee = getAbsoluteAddress(program, pointerAddress);
		if (pointee != null) {
			Address pointer = pointee.subtract(pointerSize);
			if (!TypeInfoUtils.isTypeInfoPointer(program, pointer)) {
				return Address.NO_ADDRESS;
			} return pointer;
		}
		return Address.NO_ADDRESS;
	}

	private int getSubTableCount(Address startAddress) {
		int i = 0;
		Address tiAddress = getTIAddress(startAddress);
		Address currentTIAddress = tiAddress;
		while (tiAddress.equals(currentTIAddress)) {
			if (!GnuUtils.isValidPointer(getProgram(), startAddress)) {
				break;
			}
			if(!validAddresses.contains(tiAddress)) {
				break;
			}
			currentTIAddress = getTIAddress(startAddress.add(++i * pointerSize));
		} return i;
	}

	private int getVTTableCount() throws InvalidDataTypeException {
		int tableSize = 0;
		Program program = getProgram();
		Address currentAddress = address;
		Set<ClassTypeInfo> validTypes = new HashSet<>(List.of(typeinfo.getParentModels()));
		Set<ClassTypeInfo> vParents = typeinfo.getVirtualParents();
		if (!validTypes.containsAll(vParents)) {
			for (ClassTypeInfo parent : new HashSet<>(validTypes)) {
				validTypes.addAll(List.of(parent.getParentModels()));
			}
			validTypes.addAll(vParents);
		}
		validTypes.add(typeinfo);
		validTypes.forEach((a) -> validAddresses.add(a.getAddress()));
		constructionModels = new ArrayList<>();
		while (true) {
			if (!GnuUtils.isValidPointer(program, currentAddress)) {
				break;
			}
			Address tiAddress = getTIAddress(currentAddress);
			if (tiAddress == null || tiAddress.equals(Address.NO_ADDRESS)) {
				break;
			}
			ClassTypeInfo currentType = manager.getType(tiAddress);
			if (!validTypes.contains((currentType))) {
				break;
			}
			int subCount = getSubTableCount(currentAddress);
			if(tiAddress.equals(typeinfo.getAddress())) {
				tableSize += subCount;
				currentAddress = address.add(tableSize * pointerSize);
				continue;
			}
			GnuVtable cvtable = new VtableModel(
				program, getTIPointer(currentAddress), currentType, subCount, true);
			tableSize += subCount;
			currentAddress = address.add(tableSize * pointerSize);
			constructionModels.add(cvtable);
		} return tableSize;
	}

	/**
	 * Gets the number of elements in this VttModel
	 * @return the number of VTable Table elements or 0 if invalid
	 */
	public int getElementCount() {
		if (elementCount == -1) {
			try {
				elementCount = getVTTableCount();
			} catch (InvalidDataTypeException e) {
				elementCount = 0;
			}
		}
		return elementCount;
	}

	/**
	 * Gets the DataType for this VttModel
	 * @return the DataType for this VttModel
	 */
	public DataType getDataType() {
		if (dataType == null) {
			DataTypeManager dtm = getProgram().getDataTypeManager();
			PointerDataType pointerDt = new PointerDataType(dtm);
			dataType = new ArrayDataType(pointerDt, getElementCount(), pointerSize, dtm);
		}
		return dataType;
	}

	@Override
	public String toString() {
		return "VTT for " + typeinfo.getFullName();
	}

}
