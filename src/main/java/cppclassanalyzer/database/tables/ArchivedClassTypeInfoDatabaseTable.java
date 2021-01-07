package cppclassanalyzer.database.tables;

import java.io.IOException;

import cppclassanalyzer.database.record.ArchivedClassTypeInfoRecord;
import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import db.*;

public class ArchivedClassTypeInfoDatabaseTable
		extends AbstractDatabaseTable<ArchivedClassTypeInfoSchema> {

	public ArchivedClassTypeInfoDatabaseTable(Table table) {
		super(table);
	}

	@Override
	public ArchivedClassTypeInfoSchema getSchema() {
		return ArchivedClassTypeInfoSchema.SCHEMA;
	}

	@Override
	@SuppressWarnings("unchecked")
	public final ArchivedClassTypeInfoRecord getRecord(long key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return getSchema().getRecord(record);
		}
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	public ArchivedClassTypeInfoRecord getRecord(Field key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return getSchema().getRecord(record);
		}
		return null;
	}
}
