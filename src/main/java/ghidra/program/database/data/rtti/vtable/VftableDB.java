package ghidra.program.database.data.rtti.vtable;

import java.nio.ByteBuffer;
import java.util.Arrays;

import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.WindowsVtableModel;
import ghidra.program.database.data.rtti.DataBaseUtils;
import ghidra.program.database.data.rtti.DataBaseUtils.ByteConvertable;
import ghidra.program.database.data.rtti.manager.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

import db.Record;

public class VftableDB extends AbstractVtableDB {

	private final VftableRecord[] records;

	public VftableDB(ProgramRttiRecordManager worker, db.Record record) {
		super(worker, record);
		ByteBuffer buf = ByteBuffer.wrap(getModelData());
		this.records = new VftableRecord[buf.getInt()];
		for (int i = 0; i < records.length; i++) {
			records[i] = new VftableRecord(buf);
		}
	}

	public VftableDB(ProgramRttiRecordManager worker, WindowsVtableModel vtable, Record record) {
		super(worker, vtable, record);
		Address[] addresses = vtable.getTableAddresses();
		Function[][] functions = vtable.getFunctionTables();
		this.records = new VftableRecord[addresses.length];
		for (int i = 0; i < records.length; i++) {
			records[i] = new VftableRecord(addresses[i], functions[i]);
		}
		int size = Arrays.stream(records)
						 .mapToInt(VftableRecord::getSize)
						 .sum();
		ByteBuffer buf = ByteBuffer.allocate(size + Integer.BYTES);
		DataBaseUtils.putObjectArray(buf, records);
		record.setBinaryData(SchemaOrdinals.RECORDS.ordinal(), buf.array());
		manager.updateRecord(record);
	}

	@Override
	public Address[] getTableAddresses() {
		return Arrays.stream(records)
					 .map(VftableRecord::getAddress)
					 .toArray(Address[]::new);
	}

	@Override
	public Function[][] getFunctionTables() {
		return Arrays.stream(records)
					 .map(VftableRecord::getFunctions)
					 .toArray(Function[][]::new);
	}

	private class VftableRecord implements ByteConvertable {

		private final long address;
		private final long[] functions;

		VftableRecord(ByteBuffer buf) {
			this.address = buf.getLong();
			this.functions = DataBaseUtils.getLongArray(buf);
		}

		VftableRecord(Address address, Function[] functions) {
			ClassTypeInfoManagerDB typeManager = getManager();
			this.address = typeManager.encodeAddress(address);
			this.functions = Arrays.stream(functions)
								   .map(Function::getEntryPoint)
								   .mapToLong(typeManager::encodeAddress)
								   .toArray();
		}

		public int getSize() {
			return Long.BYTES
				+ Integer.BYTES
				+ Long.BYTES * functions.length;
		}

		@Override
		public byte[] toBytes() {
			ByteBuffer buf = ByteBuffer.allocate(getSize());
			buf.putLong(address);
			DataBaseUtils.putLongArray(buf, functions);
			return buf.array();
		}

		Address getAddress() {
			return getManager().decodeAddress(address);
		}

		Function[] getFunctions() {
			ClassTypeInfoManagerDB typeManager = getManager();
			Listing listing = getProgram().getListing();
			return Arrays.stream(functions)
						 .mapToObj(typeManager::decodeAddress)
						 .map(listing::getFunctionAt)
						 .toArray(Function[]::new);
		}
	}

}