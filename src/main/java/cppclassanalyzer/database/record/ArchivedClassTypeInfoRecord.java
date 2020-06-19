package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.fields.ArchivedClassTypeInfoSchemaFields;
import db.Field;
import db.Schema;
import db.Table;

public final class ArchivedClassTypeInfoRecord
		extends AbstractDatabaseRecord<ArchivedClassTypeInfoSchemaFields> {

	public ArchivedClassTypeInfoRecord(Field key, Table table) {
		super(key, table);
	}

	public ArchivedClassTypeInfoRecord(Table table) {
		super(table);
	}

	public ArchivedClassTypeInfoRecord(db.Record record) {
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
