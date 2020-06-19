package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.ClassTypeInfoSchema;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;
import db.Field;
import db.Schema;
import db.Table;

public final class ClassTypeInfoRecord extends AbstractDatabaseRecord<ClassTypeInfoSchemaFields> {

	public ClassTypeInfoRecord(Field key, Table table) {
		super(key, table);
	}

	public ClassTypeInfoRecord(Table table) {
		super(table);
	}

	public ClassTypeInfoRecord(db.Record record) {
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
