package cppclassanalyzer.data.vtable;

import static cppclassanalyzer.database.schema.fields.VtableSchemaFields.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.util.Msg;

import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.record.DatabaseRecord.ByteConvertable;
import cppclassanalyzer.vs.VsVtableModel;

public class VftableDB extends AbstractVtableDB {

	private final VftableRecord[] records;

	public VftableDB(ProgramRttiRecordManager worker, VtableRecord record) {
		super(worker, record);
		ByteBuffer buf = ByteBuffer.wrap(getModelData(record));
		this.records = new VftableRecord[buf.getInt()];
		for (int i = 0; i < records.length; i++) {
			records[i] = new VftableRecord(buf);
		}
	}

	public VftableDB(ProgramRttiRecordManager worker, VsVtableModel vtable, VtableRecord record) {
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
		VtableRecord.putObjectArray(buf, records);
		record.setBinaryData(RECORDS, buf.array());
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
			this.functions = VtableRecord.getLongArray(buf);
		}

		VftableRecord(Address address, Function[] functions) {
			ClassTypeInfoManagerDB typeManager = getManager();
			this.address = typeManager.encodeAddress(address);
			long[] fKeys = null;
			try {
				fKeys = Arrays.stream(functions)
				   .map(Function::getEntryPoint)
				   .mapToLong(typeManager::encodeAddress)
				   .toArray();
			} catch (NullPointerException e) {
				Msg.error(this, e);
			}
			this.functions = fKeys;
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
			VtableRecord.setLongArray(buf, functions);
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
