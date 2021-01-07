package cppclassanalyzer.database.tables;

import java.io.IOException;

import cppclassanalyzer.database.record.ArchivedGnuVtableRecord;
import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import db.*;

public class ArchivedGnuVtableDatabaseTable extends AbstractDatabaseTable<ArchivedGnuVtableSchema> {

	public ArchivedGnuVtableDatabaseTable(Table table) {
		super(table);
	}

	@Override
	public ArchivedGnuVtableSchema getSchema() {
		return ArchivedGnuVtableSchema.SCHEMA;
	}

	@Override
	@SuppressWarnings("unchecked")
	public final ArchivedGnuVtableRecord getRecord(long key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return getSchema().getRecord(record);
		}
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	public ArchivedGnuVtableRecord getRecord(Field key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return getSchema().getRecord(record);
		}
		return null;
	}

}
