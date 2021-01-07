package cppclassanalyzer.database.tables;

import java.io.IOException;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.schema.ClassTypeInfoSchema;
import db.*;

public class ClassTypeInfoDatabaseTable extends AbstractDatabaseTable<ClassTypeInfoSchema> {

	public ClassTypeInfoDatabaseTable(Table table) {
		super(table);
	}

	@Override
	public ClassTypeInfoSchema getSchema() {
		return ClassTypeInfoSchema.SCHEMA;
	}

	@Override
	@SuppressWarnings("unchecked")
	public final ClassTypeInfoRecord getRecord(long key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return ClassTypeInfoSchema.SCHEMA.getRecord(record);
		}
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	public ClassTypeInfoRecord getRecord(Field key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return ClassTypeInfoSchema.SCHEMA.getRecord(record);
		}
		return null;
	}

}
