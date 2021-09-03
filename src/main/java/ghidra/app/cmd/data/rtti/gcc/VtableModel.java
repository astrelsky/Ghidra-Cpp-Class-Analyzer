package ghidra.app.cmd.data.rtti.gcc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

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
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

/**
 * Model for GNU Vtables
 */
public final class VtableModel implements GnuVtable {

	public static final String SYMBOL_NAME = "vtable";
	public static final String CONSTRUCTION_SYMBOL_NAME = "construction-"+SYMBOL_NAME;
	public static final String DESCRIPTION = "Vtable Model";
	public static final String MANGLED_PREFIX = "_ZTV";

	private Program program;
	private Address address;
	private static final int FUNCTION_TABLE_ORDINAL = 2;
	private static final int MAX_PREFIX_ELEMENTS = 3;
	private int arrayCount;
	private boolean construction;
	private Set<Function> functions = new HashSet<>();
	private ClassTypeInfo type = null;
	private List<VtablePrefixModel> vtablePrefixes;

	public static GnuVtable getVtable(Program program, Address address) {
		return getVtable(program, address, null);
	}

	public static GnuVtable getVtable(Program program, Address address, ClassTypeInfo type) {
		try {
			return new VtableModel(program, address, type);
		} catch (InvalidDataTypeException e) {
			return NO_VTABLE;
		}
	}

	VtableModel(Program program, Address address) throws InvalidDataTypeException {
		this(program, address, null, -1, false);
	}

	VtableModel(Program program, Address address, ClassTypeInfo type)
		throws InvalidDataTypeException {
			this(program, address, type, -1, false);
	}

	/**
	 * Constructs a new VtableModel
	 *
	 * @param program	  program the vtable is in.
	 * @param address	  starting address of the vtable or the first typeinfo pointer.
	 * @param type		 the ClassTypeInfo this vtable belongs to.
	 * @param arrayCount   the maximum vtable table count, if known.
	 * @param construction true if this should be a construction vtable.
	 * @throws InvalidDataTypeException
	 */
	VtableModel(Program program, Address address, ClassTypeInfo type,
			int arrayCount, boolean construction) throws InvalidDataTypeException {
			this.program = program;
			this.address = address;
			this.type = type;
			this.arrayCount = arrayCount;
			this.construction = construction;
			ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
			if (TypeInfoUtils.isTypeInfoPointer(program, address)) {
				if (this.type == null) {
					Address typeAddress = getAbsoluteAddress(program, address);
					this.type = manager.getType(typeAddress);
				}
			} else if (this.type == null) {
				int length = VtableUtils.getNumPtrDiffs(program, address);
				DataType ptrdiff_t = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
				Address typePointerAddress = address.add(length * ptrdiff_t.getLength());
				Address typeAddress = getAbsoluteAddress(program, typePointerAddress);
				this.type = manager.getType(typeAddress);
			}
			setupVtablePrefixes();
			if (vtablePrefixes.isEmpty()) {
				throw new InvalidDataTypeException(
					String.format("The vtable at %s is empty", address));
			}
	}

	@Override
	public ClassTypeInfo getTypeInfo() {
		if (type == null) {
			type = VtableUtils.getTypeInfo(program, address);
		}
		return type;
	}

	@Override
	public int hashCode() {
		getTypeInfo();
		if (type != null) {
			return type.hashCode();
		}
		return super.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (!(object instanceof GnuVtable)) {
			return false;
		}
		if (object == NO_VTABLE) {
			return this == object;
		}
		getTypeInfo();
		ClassTypeInfo otherType = ((VtableModel) object).getTypeInfo();
		if (type != null && otherType != null) {
			return type.equals(otherType);
		}
		return super.equals(object);
	}

	/**
	 * Gets the corrected start address of the vtable.
	 *
	 * @return the correct start address or NO_ADDRESS if invalid.
	 */
	public Address getAddress() {
		return address;
	}

	@Override
	public Address[] getTableAddresses() {
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
	public Function[][] getFunctionTables() {
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
	public boolean containsFunction(Function function) {
		if (functions.isEmpty()) {
			getFunctionTables();
		} return functions.contains(function);
	}

	/**
	 * @see ghidra.program.model.data.DataType#getLength()
	 * @return the vtable length
	 */
	@Override
	public int getLength() {
		if (Vtable.isValid(this)) {
			int size = 0;
			for (VtablePrefixModel prefix : vtablePrefixes) {
				size += prefix.getPrefixSize();
			}
			return size;
		}
		return 0;
	}

	@Override
	public long getOffset(int index, int ordinal) {
		if (ordinal >= getElementCount()) {
			return Long.MAX_VALUE;
		}
		return vtablePrefixes.get(index).getBaseOffset(ordinal);
	}

	/**
	 * Gets the number of vtable_prefix's in this vtable
	 *
	 * @return the number of vtable_prefix's in this vtable
	 */
	public int getElementCount() {
		return vtablePrefixes.size();
	}

	private Address getNextPrefixAddress() {
		int size = 0;
		for (VtablePrefixModel prefix : vtablePrefixes) {
			size += prefix.getPrefixSize();
		}
		return address.add(size);
	}

	@Override
	public List<DataType> getDataTypes() {
		List<DataType> result = new ArrayList<>(vtablePrefixes.size() * MAX_PREFIX_ELEMENTS);
		for (VtablePrefixModel prefix : vtablePrefixes) {
			result.addAll(prefix.dataTypes);
		}
		return result;
	}

	private void setupVtablePrefixes() {
		vtablePrefixes = new ArrayList<>();
		ClassTypeInfo tmpType;
		if (type instanceof ClassTypeInfoDB) {
			ProgramClassTypeInfoManager manager =
				(ProgramClassTypeInfoManager) ((ClassTypeInfoDB) type).getManager();
			tmpType = (ClassTypeInfo) manager.getTypeInfo(type.getAddress(), false);
			if (tmpType == null) {
				return;
			}
		} else {
			tmpType = type;
		}
		int count = construction ? 2 : ClassTypeInfoUtils.getMaxVtableCount(tmpType);
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

	@Override
	public List<VtablePrefix> getPrefixes() {
		return Collections.unmodifiableList(vtablePrefixes);
	}

	public boolean isConstruction() {
		return construction;
	}

	private class VtablePrefixModel implements VtablePrefix {

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
				//int pointerSize = program.getDefaultPointerSize();
				if (TypeInfoUtils.isTypeInfoPointer(program, prefixAddress)) {
					this.prefixAddress = prefixAddress.subtract(numPtrDiffs * ptrdiff_t.getLength());
				}
				dataTypes.add(new ArrayDataType(ptrdiff_t, numPtrDiffs, ptrdiff_t.getLength(), dtm));
				dataTypes.add(new PointerDataType(null, -1, dtm));
				Address tableAddress = this.prefixAddress.add(getPrefixSize());
				int tableSize = VtableUtils.getFunctionTableLength(program, tableAddress);
				if (tableSize > 0) {
					ArrayDataType table = new ArrayDataType(
						PointerDataType.dataType, tableSize, -1, dtm);
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

		@Override
		public List<Long> getOffsets() {
			try {
				Array array = (Array) dataTypes.get(0);
				MemoryBufferImpl prefixBuf = new MemoryBufferImpl(
					program.getMemory(), prefixAddress);
				int length = array.getElementLength();
				long[] result = new long[array.getNumElements()];
				for (int i = 0; i < result.length; i++) {
					result[i] = prefixBuf.getBigInteger(i*length, length, true).longValue();
				}
				return Arrays.stream(result)
					.boxed()
					.collect(Collectors.toUnmodifiableList());
			} catch (MemoryAccessException e) {
				Msg.error(this, "Failed to retreive base offsets at "+prefixAddress, e);
				return Collections.emptyList();
			}
		}

		private long getBaseOffset(int ordinal) {
			Array array = (Array) dataTypes.get(0);
			if (ordinal >= array.getElementLength()) {
				return -1;
			}
			return getOffsets().get(ordinal);
		}

		@Override
		public List<Function> getFunctionTable() {
			Function[] result = VtableUtils.getFunctionTable(program, getTableAddress());
			return Collections.unmodifiableList(Arrays.asList(result));
		}

		@Override
		public List<DataType> getDataTypes() {
			return Collections.unmodifiableList(dataTypes);
		}

		@Override
		public Address getAddress() {
			return prefixAddress;
		}
	}
}
