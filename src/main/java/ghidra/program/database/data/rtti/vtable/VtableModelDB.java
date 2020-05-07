package ghidra.program.database.data.rtti.vtable;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.DataBaseUtils;
import ghidra.program.database.data.rtti.DataBaseUtils.ByteConvertable;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable.ArchivedVtablePrefix;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import com.google.common.primitives.Longs;

public final class VtableModelDB extends AbstractVtableDB implements GnuVtable {

	private final VtableModelPrefixRecord[] records;

	public VtableModelDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractVtableDB> cache,
			long key) {
		super(manager, cache, key);
		ByteBuffer buf = ByteBuffer.wrap(getModelData());
		this.records = new VtableModelPrefixRecord[buf.getInt()];
		for (int i = 0; i < records.length; i++) {
			records[i] = new VtableModelPrefixRecord(buf);
		}
	}

	public VtableModelDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractVtableDB> cache,
			VtableModel vtable, db.Record record) {
		super(manager, cache, vtable, record);
		this.records = vtable.getPrefixes().stream()
			.map(VtableModelPrefixRecord::new)
			.toArray(VtableModelPrefixRecord[]::new);
		int size = Arrays.stream(records)
				.mapToInt(VtableModelPrefixRecord::getSize)
				.sum();
		ByteBuffer buf = ByteBuffer.allocate(size + Integer.BYTES);
		DataBaseUtils.putObjectArray(buf, records);
		record.setBinaryData(SchemaOrdinals.RECORDS.ordinal(), buf.array());
		manager.updateRecord(record);
	}

	public VtableModelDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractVtableDB> cache,
		ArchivedGnuVtable vtable, db.Record record) {
		super(manager, cache, vtable, record);
		Program program = manager.getProgram();
		Address address = vtable.getAddress(program);
		ArchivedVtablePrefix[] prefixes = vtable.getPrefixes();
		this.records = new VtableModelPrefixRecord[prefixes.length];
		for (int i = 0; i < records.length; i++) {
			ArchivedVtablePrefix prefix = prefixes[i];
			Function[] functions = ArchivedGnuVtable.getFunctions(program, prefix);
			records[i] = new VtableModelPrefixRecord(address, functions, prefix.offsets);
			address = address.add(records[i].getLength());
		}

	}

	@Override
	public long getOffset(int index, int ordinal) {
		return records[index].offsets[ordinal];
	}

	@Override
	public Address[] getTableAddresses() {
		return Arrays.stream(records)
				.map(VtableModelPrefixRecord::getAddress)
				.toArray(Address[]::new);
	}

	@Override
	public Function[][] getFunctionTables() {
		return Arrays.stream(records)
				.map(VtableModelPrefixRecord::getFunctions)
				.toArray(Function[][]::new);
	}

	@Override
	public List<DataType> getDataTypes() {
		// 3 datatypes per prefix
		List<DataType> types = new ArrayList<>(3 * records.length);
		DataTypeManager dtm = getProgram().getDataTypeManager();
		DataType tiPointer = new PointerDataType(null, -1, dtm);
		DataType ptrdiff_t = GnuUtils.getPtrDiff_t(dtm);
		for (VtableModelPrefixRecord record : records) {
			DataType offsets =
				new ArrayDataType(ptrdiff_t, record.offsets.length, ptrdiff_t.getLength(), dtm);
			types.add(offsets);
			types.add(tiPointer);
			if (record.functions.length > 0) {
				DataType functions =
					new ArrayDataType(PointerDataType.dataType, record.functions.length, -1, dtm);
				types.add(functions);
			}
		}
		return types;
	}

	@Override
	public List<VtablePrefix> getPrefixes() {
		return List.of(records);
	}

	class VtableModelPrefixRecord implements VtablePrefix, ByteConvertable {
		private final long address;
		private final long[] offsets;
		private final long[] functions;

		VtableModelPrefixRecord(ByteBuffer buf) {
			this.address = buf.getLong();
			this.offsets = DataBaseUtils.getLongArray(buf);
			this.functions = DataBaseUtils.getLongArray(buf);

		}

		VtableModelPrefixRecord(VtablePrefix prefix) {
			this.address = manager.encodeAddress(prefix.getAddress());
			this.offsets = Longs.toArray(prefix.getOffsets());
			this.functions = prefix.getFunctionTable()
				.stream()
				.map(f -> {return f != null ? f.getEntryPoint() : Address.NO_ADDRESS;})
				.mapToLong(manager::encodeAddress)
				.toArray();
		}

		VtableModelPrefixRecord(Address address, Function[] functions, long[] offsets) {
			this.address = manager.encodeAddress(address);
			this.offsets = offsets;
			this.functions = Arrays.stream(functions)
				.map(Function::getEntryPoint)
				.mapToLong(manager::encodeAddress)
				.toArray();
		}

		int getLength() {
			Program program = getProgram();
			DataType ptrdiff_t = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
			return ptrdiff_t.getLength() * offsets.length
				+ program.getDefaultPointerSize() * (1 + functions.length);
		}

		int getSize() {
			return Long.BYTES + Integer.BYTES * 2 + offsets.length * Long.BYTES +
				functions.length * Long.BYTES;
		}

		@Override
		public byte[] toBytes() {
			ByteBuffer buf = ByteBuffer.allocate(getSize());
			buf.putLong(address);
			DataBaseUtils.putLongArray(buf, offsets);
			DataBaseUtils.putLongArray(buf, functions);
			return buf.array();
		}

		@Override
		public Address getAddress() {
			return manager.decodeAddress(address);
		}

		private Function[] getFunctions() {
			Listing listing = getProgram().getListing();
			return Arrays.stream(functions)
					.mapToObj(manager::decodeAddress)
					.map(listing::getFunctionAt)
					.toArray(Function[]::new);
		}

		@Override
		public List<Long> getOffsets() {
			return Arrays.stream(offsets)
				.boxed()
				.collect(Collectors.toUnmodifiableList());
		}

		@Override
		public List<Function> getFunctionTable() {
			// the array is regenerated each time. not required to be immutable
			return Arrays.asList(getFunctions());
		}

		@Override
		public List<DataType> getDataTypes() {
			DataTypeManager dtm = getProgram().getDataTypeManager();
			DataType ptrDiff = GnuUtils.getPtrDiff_t(dtm);
			List<DataType> result = new ArrayList<>(3);
			result.add(new ArrayDataType(ptrDiff, offsets.length, ptrDiff.getLength(), dtm));
			result.add(new PointerDataType(null, -1, dtm));
			result.add(new ArrayDataType(
				PointerDataType.dataType, functions.length, -1, dtm));
			return result;
		}
	}

}