package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.ClassTypeInfoSchema;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;
import db.Schema;

public final class ClassTypeInfoRecord extends AbstractDatabaseRecord<ClassTypeInfoSchemaFields> {

	public ClassTypeInfoRecord(db.DBRecord record) {
		super(record);
	}

	@Override
	public Schema getSchema() {
		return ClassTypeInfoSchema.SCHEMA;
	}

	@Override
	public ClassTypeInfoRecord copy() {
		return new ClassTypeInfoRecord(getRecord().copy());
	}

}
