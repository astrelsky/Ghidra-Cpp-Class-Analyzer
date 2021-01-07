package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.fields.ArchivedClassTypeInfoSchemaFields;
import db.*;

public final class ArchivedClassTypeInfoRecord
		extends AbstractDatabaseRecord<ArchivedClassTypeInfoSchemaFields> {

	public ArchivedClassTypeInfoRecord(Field key, Table table) {
		super(key, table);
	}

	public ArchivedClassTypeInfoRecord(Table table) {
		super(table);
	}

	public ArchivedClassTypeInfoRecord(DBRecord record) {
		super(record);
	}

	@Override
	public Schema getSchema() {
		return ArchivedClassTypeInfoSchema.SCHEMA;
	}

	@Override
	public ArchivedClassTypeInfoRecord copy() {
		return new ArchivedClassTypeInfoRecord(getRecord().copy());
	}

}
