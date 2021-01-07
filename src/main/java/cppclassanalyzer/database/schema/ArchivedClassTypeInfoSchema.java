package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.ArchivedClassTypeInfoRecord;
import cppclassanalyzer.database.schema.fields.ArchivedClassTypeInfoSchemaFields;
import db.DBRecord;

public final class ArchivedClassTypeInfoSchema
		extends AbstractSchema<ArchivedClassTypeInfoRecord> {

	private static final int VERSION = 0;
	public static final ArchivedClassTypeInfoSchema SCHEMA =
		new ArchivedClassTypeInfoSchema(VERSION);
	public static final int[] INDEXED_COLUMNS = new int[] {
		ArchivedClassTypeInfoSchemaFields.MANGLED_SYMBOL.ordinal(),
		ArchivedClassTypeInfoSchemaFields.DATATYPE_ID.ordinal()
	};

	private ArchivedClassTypeInfoSchema(int version) {
		super(version, "Key",
			ArchivedClassTypeInfoSchemaFields.getFields(),
			ArchivedClassTypeInfoSchemaFields.getFieldNames());
	}

	@Override
	public ArchivedClassTypeInfoRecord getRecord(DBRecord record) {
		return new ArchivedClassTypeInfoRecord(record);
	}

}
