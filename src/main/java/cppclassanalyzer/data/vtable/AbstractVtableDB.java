package cppclassanalyzer.data.vtable;

import static cppclassanalyzer.database.schema.fields.VtableSchemaFields.*;

import java.util.Arrays;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.program.database.DatabaseObject;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;

import cppclassanalyzer.database.record.VtableRecord;

public abstract class AbstractVtableDB extends DatabaseObject implements Vtable {

	public static final String VTABLE_TABLE_NAME = "Vtable Table";

	protected final ProgramRttiRecordManager manager;

	AbstractVtableDB(ProgramRttiRecordManager worker, VtableRecord record) {
		super(worker.getVtableCache(), record.getKey());
		this.manager = worker;
	}

	AbstractVtableDB(ProgramRttiRecordManager worker, Vtable vtable,
			VtableRecord record) {
		super(worker.getVtableCache(), record.getKey());
		this.manager = worker;
		long classKey = getManager().getTypeKey(vtable.getTypeInfo().getAddress());
		Address address = null;
		if (vtable instanceof VtableModel) {
			address = ((VtableModel) vtable).getAddress();
		} else {
			address = vtable.getTableAddresses()[0];
		}
		record.setLongValue(ADDRESS, getManager().encodeAddress(address));
		record.setLongValue(CLASS, classKey);
		manager.updateRecord(record);
	}

	AbstractVtableDB(ProgramRttiRecordManager worker, ArchivedGnuVtable vtable,
			VtableRecord record) {
		this(worker, record);
	}

	protected final ClassTypeInfoManagerDB getManager() {
		return (ClassTypeInfoManagerDB) manager.getManager();
	}

	public void setClassKey(long key) {
		VtableRecord record = getRecord();
		record.setLongValue(CLASS, key);
		manager.updateRecord(record);
	}

	public Address getAddress() {
		VtableRecord record = getRecord();
		return getManager().decodeAddress(record.getLongValue(ADDRESS));
	}

	public Program getProgram() {
		return getManager().getProgram();
	}

	protected VtableRecord getRecord() {
		VtableRecord record = manager.getVtableRecord(getKey());
		if (record == null) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: vtable record no longer exists");
		}
		return record;
	}

	protected byte[] getModelData() {
		return getRecord().getBinaryData(RECORDS);
	}

	@Override
	public ClassTypeInfo getTypeInfo() {
		VtableRecord record = getRecord();
		return manager.getType(record.getLongValue(CLASS));
	}

	@Override
	public boolean containsFunction(Function function) {
		return Arrays.stream(getFunctionTables()).flatMap((a) -> Arrays.stream(a))
					 .filter(function::equals)
					 .findAny()
					 .isPresent();
	}

	@Override
	protected boolean refresh() {
		return getManager().containsRecord(this);
	}

	protected static Address getEntryPoint(Function function) {
		return function != null ? function.getEntryPoint() : Address.NO_ADDRESS;
	}
}