package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import cppclassanalyzer.database.schema.fields.ArchivedGnuVtableSchemaFields;
import db.*;

public final class ArchivedGnuVtableRecord extends AbstractDatabaseRecord<ArchivedGnuVtableSchemaFields> {

	public ArchivedGnuVtableRecord(Field key, Table table) {
		super(key, table);
	}

	public ArchivedGnuVtableRecord(Table table) {
		super(table);
	}

	public ArchivedGnuVtableRecord(DBRecord record) {
		super(record);
	}

	@Override
	public Schema getSchema() {
		return ArchivedGnuVtableSchema.SCHEMA;
	}

	@Override
	public ArchivedGnuVtableRecord copy() {
		return new ArchivedGnuVtableRecord(getRecord().copy());
	}

}
