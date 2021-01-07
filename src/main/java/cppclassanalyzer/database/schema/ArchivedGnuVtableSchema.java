package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.ArchivedGnuVtableRecord;
import cppclassanalyzer.database.schema.fields.ArchivedGnuVtableSchemaFields;
import db.DBRecord;

public final class ArchivedGnuVtableSchema extends AbstractSchema<ArchivedGnuVtableRecord> {

	private static final int VERSION = 0;
	public static final ArchivedGnuVtableSchema SCHEMA = new ArchivedGnuVtableSchema(VERSION);
	public static final int[] INDEXED_COLUMNS = new int[] {
		ArchivedGnuVtableSchemaFields.MANGLED_SYMBOL.ordinal()
	};

	private ArchivedGnuVtableSchema(int version) {
		super(version, "Key",
			ArchivedGnuVtableSchemaFields.getFields(),
			ArchivedGnuVtableSchemaFields.getFieldNames());
	}

	@Override
	public ArchivedGnuVtableRecord getRecord(DBRecord record) {
		return new ArchivedGnuVtableRecord(record);
	}

}
