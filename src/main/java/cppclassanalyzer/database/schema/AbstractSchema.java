package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.DatabaseRecord;
import db.Field;
import db.Schema;

public abstract class AbstractSchema<T extends DatabaseRecord<?>> extends Schema
		implements DatabaseSchema<T> {

	protected AbstractSchema(int version, Class<? extends Field> keyFieldClass, String keyName,
			Class<?>[] fieldClasses, String[] fieldNames) {
		super(version, keyFieldClass, keyName, fieldClasses, fieldNames);
	}

	protected AbstractSchema(int version, String keyName, Class<?>[] fieldClasses,
			String[] fieldNames) {
		super(version, keyName, fieldClasses, fieldNames);
	}

	@Override
	public final T getNewRecord(long key) {
		return getRecord(createRecord(key));
	}

	@Override
	public final T getNewRecord(Field key) {
		return getRecord(createRecord(key));
	}
}