package cppclassanalyzer.database.tables;

import java.io.IOException;

import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.schema.VtableSchema;
import db.*;

public class VtableDatabaseTable extends AbstractDatabaseTable<VtableSchema> {

	public VtableDatabaseTable(Table table) {
		super(table);
	}

	@Override
	public VtableSchema getSchema() {
		return VtableSchema.SCHEMA;
	}

	@Override
	@SuppressWarnings("unchecked")
	public final VtableRecord getRecord(long key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return VtableSchema.SCHEMA.getRecord(record);
		}
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	public VtableRecord getRecord(Field key) throws IOException {
		DBRecord record = getRawRecord(key);
		if (record != null) {
			return VtableSchema.SCHEMA.getRecord(record);
		}
		return null;
	}

}
