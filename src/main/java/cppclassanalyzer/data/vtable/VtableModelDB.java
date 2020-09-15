package cppclassanalyzer.data.vtable;

import static cppclassanalyzer.database.schema.fields.VtableSchemaFields.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable.ArchivedVtablePrefix;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import com.google.common.primitives.Longs;

import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.record.DatabaseRecord.ByteConvertable;

public final class VtableModelDB extends AbstractVtableDB implements GnuVtable {

	private final VtableModelPrefixRecord[] records;

	public VtableModelDB(ProgramRttiRecordManager worker, VtableRecord record) {
		super(worker, record);
		ByteBuffer buf = ByteBuffer.wrap(getModelData(record));
		this.records = new VtableModelPrefixRecord[buf.getInt()];
		for (int i = 0; i < records.length; i++) {
			records[i] = new VtableModelPrefixRecord(buf);
		}
	}

	public VtableModelDB(ProgramRttiRecordManager worker, GnuVtable vtable, VtableRecord record) {
		super(worker, vtable, record);
		this.records = vtable.getPrefixes().stream()
			.map(VtableModelPrefixRecord::new)
			.toArray(VtableModelPrefixRecord[]::new);
		int size = Arrays.stream(records)
				.mapToInt(VtableModelPrefixRecord::getSize)
				.sum();
		ByteBuffer buf = ByteBuffer.allocate(size + Integer.BYTES);
		VtableRecord.putObjectArray(buf, records);
		record.setBinaryData(RECORDS, buf.array());
		manager.updateRecord(record);
	}

	public VtableModelDB(ProgramRttiRecordManager worker, ArchivedGnuVtable vtable,
			VtableRecord record) {
		super(worker, vtable, record);
		Program program = getProgram();
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
		Program program = getProgram();
		int pointerSize = program.getDefaultPointerSize();
		int ptrdiffSize = GnuUtils.getPtrDiffSize(program.getDataTypeManager());
		Address[] addresses = new Address[records.length];
		for (int i = 0; i < records.length; i++) {
			VtableModelPrefixRecord record = records[i];
			int offset = pointerSize + ptrdiffSize * record.offsets.length;
			addresses[i] = record.getAddress().add(offset);
		}
		return addresses;
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
			this.offsets = VtableRecord.getLongArray(buf);
			this.functions = VtableRecord.getLongArray(buf);

		}

		VtableModelPrefixRecord(VtablePrefix prefix) {
			ClassTypeInfoManagerDB typeManager = getManager();
			this.address = typeManager.encodeAddress(prefix.getAddress());
			this.offsets = Longs.toArray(prefix.getOffsets());
			this.functions = prefix.getFunctionTable()
				.stream()
				.map(f -> {return f != null ? f.getEntryPoint() : Address.NO_ADDRESS;})
				.mapToLong(typeManager::encodeAddress)
				.toArray();
		}

		VtableModelPrefixRecord(Address address, Function[] functions, long[] offsets) {
			ClassTypeInfoManagerDB typeManager = getManager();
			this.address = typeManager.encodeAddress(address);
			this.offsets = offsets;
			this.functions = Arrays.stream(functions)
				.map(Function::getEntryPoint)
				.mapToLong(typeManager::encodeAddress)
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
			VtableRecord.setLongArray(buf, offsets);
			VtableRecord.setLongArray(buf, functions);
			return buf.array();
		}

		@Override
		public Address getAddress() {
			return getManager().decodeAddress(address);
		}

		private Function[] getFunctions() {
			ClassTypeInfoManagerDB typeManager = getManager();
			Listing listing = getProgram().getListing();
			return Arrays.stream(functions)
				.mapToObj(typeManager::decodeAddress)
				.map(listing::getFunctionContaining)
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
