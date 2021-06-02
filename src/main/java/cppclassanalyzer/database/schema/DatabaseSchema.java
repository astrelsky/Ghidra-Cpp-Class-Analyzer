package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.DatabaseRecord;
import db.Field;

public interface DatabaseSchema<T extends DatabaseRecord<?>> {

	T getNewRecord(long key);
	T getNewRecord(Field key);
	T getRecord(db.DBRecord record);
}