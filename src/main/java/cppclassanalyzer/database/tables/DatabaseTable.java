package cppclassanalyzer.database.tables;

import java.io.IOException;

import cppclassanalyzer.database.record.DatabaseRecord;
import cppclassanalyzer.database.schema.AbstractSchema;
import db.*;

public interface DatabaseTable<T extends AbstractSchema<?>> {
	T getSchema();
	Table getTable();

	String getName();

	<R extends DatabaseRecord<?>> R getRecord(long key) throws IOException;
	<R extends DatabaseRecord<?>> R getRecord(Field key) throws IOException;
}
