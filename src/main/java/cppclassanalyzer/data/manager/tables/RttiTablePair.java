package cppclassanalyzer.data.manager.tables;

import java.io.IOException;

import cppclassanalyzer.database.schema.AbstractSchema;
import cppclassanalyzer.database.tables.DatabaseTable;
import db.Table;

public abstract class RttiTablePair<T1 extends AbstractSchema<?>, T2 extends AbstractSchema<?>> {

	private final DatabaseTable<T1> classTable;
	private final DatabaseTable<T2> vtableTable;

	RttiTablePair(DatabaseTable<T1> classTable, DatabaseTable<T2> vtableTable) {
		this.classTable = classTable;
		this.vtableTable = vtableTable;
	}

	public final T1 getTypeSchema() {
		return classTable.getSchema();
	}

	public final T2 getVtableSchema() {
		return vtableTable.getSchema();
	}

	public final Table getTypeTable() {
		return classTable.getTable();
	}

	public final Table getVtableTable() {
		return vtableTable.getTable();
	}

	public final void deleteAll() throws IOException {
		classTable.getTable().deleteAll();
		vtableTable.getTable().deleteAll();
	}
}
