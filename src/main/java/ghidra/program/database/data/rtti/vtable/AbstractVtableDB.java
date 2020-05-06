package ghidra.program.database.data.rtti.vtable;

import java.util.Arrays;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;

import db.*;

public abstract class AbstractVtableDB extends DatabaseObject implements Vtable {

	private static final int VERSION = 0;
	public static final String VTABLE_TABLE_NAME = "Vtable Table";

	public static enum SchemaOrdinals {
		ADDRESS,
		CLASS,
		RECORDS
	};

	public static final int[] INDEXED_COLUMNS = new int[] {
		SchemaOrdinals.ADDRESS.ordinal()
	};

	public static final Schema SCHEMA =
		new Schema(
			VERSION,
			"Key",
			new Class[] { LongField.class, LongField.class, BinaryField.class },
			new String[] { "Address", "ClassTypeInfo Key", "Sub Records" }
		);

	protected final ClassTypeInfoManagerDB manager;

	AbstractVtableDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractVtableDB> cache,
		long key) {
		super(cache, key);
		this.manager = manager;
	}

	AbstractVtableDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractVtableDB> cache,
			Vtable vtable, db.Record record) {
		super(cache, record.getKey());
		this.manager = manager;
		long classKey = manager.getClassKey(vtable.getTypeInfo().getAddress());
		Address address = null;
		if (vtable instanceof VtableModel) {
			address = ((VtableModel) vtable).getAddress();
		} else {
			address = vtable.getTableAddresses()[0];
		}
		record.setLongValue(SchemaOrdinals.ADDRESS.ordinal(), manager.encodeAddress(address));
		record.setLongValue(SchemaOrdinals.CLASS.ordinal(), classKey);
		manager.updateRecord(record);
	}

	AbstractVtableDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractVtableDB> cache,
			ArchivedGnuVtable vtable, db.Record record) {
		super(cache, record.getKey());
		this.manager = manager;

	}

	public void setClassKey(long key) {
		db.Record record = getRecord();
		record.setLongValue(SchemaOrdinals.CLASS.ordinal(), key);
		manager.updateRecord(record);
	}

	public Address getAddress() {
		db.Record record = getRecord();
		return manager.decodeAddress(record.getLongValue(SchemaOrdinals.ADDRESS.ordinal()));
	}

	public Program getProgram() {
		return manager.getProgram();
	}

	protected db.Record getRecord() {
		db.Record record = manager.getRecord(this);
		if (record == null) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: vtable record no longer exists");
		}
		return record;
	}

	protected byte[] getModelData() {
		return getRecord().getBinaryData(SchemaOrdinals.RECORDS.ordinal());
	}

	@Override
	public ClassTypeInfo getTypeInfo() {
		db.Record record = getRecord();
		return manager.getClass(record.getLongValue(SchemaOrdinals.CLASS.ordinal()));
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
		return manager.containsRecord(this);
	}

	protected static Address getEntryPoint(Function function) {
		return function != null ? function.getEntryPoint() : Address.NO_ADDRESS;
	}
}