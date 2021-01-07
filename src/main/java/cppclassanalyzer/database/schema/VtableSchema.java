package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.schema.fields.VtableSchemaFields;
import db.DBRecord;

public final class VtableSchema extends AbstractSchema<VtableRecord> {

	private static final int VERSION = 0;
	public static final VtableSchema SCHEMA = new VtableSchema(VERSION);
	public static final int[] INDEXED_COLUMNS = new int[] {
		VtableSchemaFields.ADDRESS.ordinal()
	};

	private VtableSchema(int version) {
		super(version, "Key",
			VtableSchemaFields.getFields(),
			VtableSchemaFields.getFieldNames());
	}

	@Override
	public VtableRecord getRecord(DBRecord record) {
		return new VtableRecord(record);
	}

}
