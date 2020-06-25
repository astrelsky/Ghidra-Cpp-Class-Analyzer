package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;

public final class ClassTypeInfoSchema extends AbstractSchema<ClassTypeInfoRecord> {

	private static final int VERSION = 0;
	public static final ClassTypeInfoSchema SCHEMA = new ClassTypeInfoSchema(VERSION);
	public static final int[] INDEXED_COLUMNS = new int[] {
		ClassTypeInfoSchemaFields.ADDRESS.ordinal(),
		ClassTypeInfoSchemaFields.DATATYPE_ID.ordinal()
	};

	private ClassTypeInfoSchema(int version) {
		super(version, "Key",
			ClassTypeInfoSchemaFields.getFields(),
			ClassTypeInfoSchemaFields.getFieldNames());
	}

	@Override
	public ClassTypeInfoRecord getRecord(db.Record record) {
		return new ClassTypeInfoRecord(record);
	}

}
