package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

import ghidra.program.model.address.*;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class VtableUtils {

	// that's still a awful lot
	public static final int MAX_PTR_DIFFS = 25;

	private VtableUtils() {}

	@FunctionalInterface
	private interface IntToLongFunction {
		long applyAsLong(int value) throws MemoryAccessException;
	}

	/**
	 * Gets the number of ptrdiff_t's in the vtable_prefix at the address
	 * @param program the program containing the vtable_prefix
	 * @param address the address of the vtable_prefix
	 * @return the number of ptrdiff_t's in the vtable_prefix at the address
	 */
	public static int getNumPtrDiffs(Program program, Address address) {
		return getNumPtrDiffs(program, address, -1);
	}

	/**
	 * Gets the size of the ptrdiff_t array at the start of a vtable_prefix
	 * @param program the program containing the ptrdiff_t array
	 * @param address the address of the ptrdiff_t array
	 * @param maxLength the max length for the ptrdiff_t array
	 * @return the number of ptrdiff_t's in the array or 0 if invalid
	 */
	public static int getNumPtrDiffs(Program program, Address address, int maxLength) {
		/**
		 * This is not pretty. The rules I have found are as follows.
		 * Positive values may only repeate when going down.
		 * Negative values and 0 may repeate.
		 * Values may not go from negative/positive and then back or vise-versa.
		 * AddressOverflowException and MemoryAccessException may only occur when
		 * counting upwards from the typeinfo pointer.
		 * Most classes within libstdc++ contain no more than 2 ptrdiff_t's,
		 * however this was written to be able to withstand large inheritance chains.
		 */
		if (maxLength < 0) {
			maxLength = MAX_PTR_DIFFS;
		}
		Listing listing = program.getListing();
		Data before = listing.getDefinedDataBefore(address);
		Data after = listing.getDefinedDataAfter(address);
		Data containing = listing.getDefinedDataContaining(address);
		if (isValidData(containing)) {
			AddressRangeImpl set;
			if (before.equals(containing)) {
				set = new AddressRangeImpl(before.getAddress(), after.getAddress());
			} else {
				while(isValidData(before)) {
					before = listing.getDefinedDataBefore(before.getAddress());
				}
				if (after == null) {
					set = new AddressRangeImpl(before.getMaxAddress(), program.getMaxAddress());
				} else {
					AddressSpace beforeSpace = before.getMaxAddress().getAddressSpace();
					AddressSpace afterSpace = after.getAddress().getAddressSpace();
					if (!beforeSpace.equals(afterSpace)) {
						return 0;
					}
					set = new AddressRangeImpl(before.getMaxAddress(), after.getAddress());
				}
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
				return getNumPtrDiffs(program, address.subtract(ptrDiffSize), set, true, maxLength);
			}
			return getNumPtrDiffs(program, address, set, false, maxLength);
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
		AddressRange range, boolean reverse, int maxLength) {
			MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), address);
			DataType ptrdiff_t = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
			int length = ptrdiff_t.getLength();
			int direction = reverse ? -1 : 1;
			int count = 0;
			long value = 0;
			List<Long> values = new ArrayList<>();
			IntToLongFunction getValue = length == 8 ? buf::getLong : buf::getInt;
			while (range.contains(buf.getAddress()) && count < maxLength) {
				try {
					if (GnuUtils.isDataPointer(buf) && !(getValue.applyAsLong(0) == 0)) {
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
	 * Returns the TypeInfo Model this vtable points to
	 * @param program program the vtable is in
	 * @param address address of the start of the vtable
	 * @return the pointed to TypeInfo Model or null if not found
	 */
	public static ClassTypeInfo getTypeInfo(Program program, Address address) {
		ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
		DataTypeManager dtm = program.getDataTypeManager();
		int ptrDiffSize = GnuUtils.getPtrDiffSize(dtm);
		int numPtrDiffs = getNumPtrDiffs(program, address);
		Address currentAddress = address.add(ptrDiffSize * numPtrDiffs);
		if (TypeInfoUtils.isTypeInfoPointer(program, currentAddress)) {
			return manager.getType(getAbsoluteAddress(program, currentAddress));
		}
		return null;
	}

	/**
	 * Gets the number of elements in the vtable_prefix's function table
	 * @param program the program containing the function table
	 * @param address the address of the function table
	 * @return the number of elements in the vtable_prefix's function table
	 */
	public static int getFunctionTableLength(Program program, Address address) {
		int tableSize = 0;
		MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), address);
		int pointerSize = program.getDefaultPointerSize();
		while (GnuUtils.isNullPointer(buf)) {
			tableSize++;
			try {
				buf.advance(pointerSize);
			} catch (AddressOverflowException e) {
				return 0;
			}
		}
		while (GnuUtils.isFunctionPointer(program, buf.getAddress())) {
			if (isNotDefinedPointerData(program, buf.getAddress())) {
				break;
			}
			tableSize++;
			try {
				buf.advance(pointerSize);
			} catch (AddressOverflowException e) {
				// Assume table ends at end of address set
				break;
			}
		}
		return tableSize;
	}

	private static boolean isNotDefinedPointerData(Program program, Address address) {
		Data data = program.getListing().getDataAt(address);
		if (data != null && data.isDefined()) {
			return !data.isPointer();
		}
		return false;
	}

	/**
	 * Gets the function table at the specified address.
	 * @param program the program containing the function table
	 * @param address the address of the function table
	 * @return a Function[] representing the function table.
	 */
	public static Function[] getFunctionTable(Program program, Address address) {
		Function[] functions = new Function[getFunctionTableLength(program, address)];
		int pointerSize = program.getDefaultPointerSize();
		for (int i = 0; i < functions.length; i++) {
			Address functionAddress = getFunctionAddress(program, address.add(i * pointerSize));
			if (functionAddress.getOffset() != 0) {
				functions[i] = createFunction(program, functionAddress);
			} else {
				functions[i] = null;
			}
		}
		return functions;
	}

	private static Address getFunctionAddress(Program program, Address currentAddress) {
		Address functionAddress = getAbsoluteAddress(program, currentAddress);
		if (GnuUtils.hasFunctionDescriptors(program) && functionAddress.getOffset() != 0) {
			List<Relocation> relocs = program.getRelocationTable().getRelocations(currentAddress);
			if (relocs.isEmpty() || relocs.stream().allMatch(reloc -> reloc.getSymbolName() == null)) {
				return getAbsoluteAddress(program, functionAddress);
			}
		} return functionAddress;
	}

	private static Function createFunction(Program program, Address currentAddress) {
		Listing listing = program.getListing();
		Function function = listing.getFunctionContaining(currentAddress);
		if (function != null) {
			return function;
		}
		Instruction inst = listing.getInstructionContaining(currentAddress);
		if (inst == null) {
			// If it has not been disassembled, disassemble it first.
			if (program.getMemory().getBlock(currentAddress).isInitialized()) {
				DisassembleCommand cmd = new DisassembleCommand(currentAddress, null, true);
				cmd.applyTo(program);
			}
			inst = listing.getInstructionContaining(currentAddress);
			if (inst == null) {
				return null;
			}
		}
		// handle thumb mode pointer offset
		Address entry = inst.getAddress();
		CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
		cmd.applyTo(program);
		return cmd.getFunction();
	}

	/**
	 * Gets the VttModel for the specified VtableModel if one exists
	 * @param program the program containing the vtable
	 * @param vtable the vtable
	 * @return the VttModel or {@link VttModel#INVALID} if none
	 */
	public static VttModel getVttModel(Program program, GnuVtable vtable) {
		if (vtable.getTypeInfo().getTypeName().contains(TypeInfoModel.STRUCTURE_NAME)) {
			return VttModel.INVALID;
		}
		Address[] tableAddresses = vtable.getTableAddresses();
		if (tableAddresses.length == 0) {
			return VttModel.INVALID;
		}
		ReferenceManager man = program.getReferenceManager();
		Address addr = tableAddresses[0];
		Set<Address> references = CollectionUtils.asStream(man.getReferencesTo(addr))
			.map(Reference::getFromAddress)
			.filter(Predicate.not(SpecialAddress.class::isInstance))
			.collect(Collectors.toSet());
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

	public static boolean isMangled(String s) {
		return s.startsWith("_ZTV") && !s.contains("@");
	}

	public static String getSymbolName(Vtable vtable) {
		ClassTypeInfo type = vtable.getTypeInfo();
		Program program = TypeInfoUtils.getProgram(type);
		SymbolTable table = program.getSymbolTable();
		return Arrays.stream(table.getSymbols(vtable.getAddress()))
			.map(Symbol::getName)
			.filter(VtableUtils::isMangled)
			.findFirst()
			.orElseGet(() -> { return "_ZTV" + type.getTypeName(); });
	}

	public static Program getProgram(Vtable vtable) {
		ClassTypeInfo type = vtable.getTypeInfo();
		return TypeInfoUtils.getProgram(type);
	}
}
