package cppclassanalyzer.database.tables;

import java.io.IOException;

import ghidra.util.exception.AssertException;

import cppclassanalyzer.database.schema.AbstractSchema;
import db.*;

abstract class AbstractDatabaseTable<T extends AbstractSchema<?>> implements DatabaseTable<T> {

	private final Table table;

	AbstractDatabaseTable(Table table) {
		if (!table.getSchema().equals(getSchema())) {
			throw new AssertException("Schema's do not match");
		}
		this.table = table;
	}

	@Override
	public final Table getTable() {
		return table;
	}

	@Override
	public final String getName() {
		return table.getName();
	}

	protected final DBRecord getRawRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	protected final DBRecord getRawRecord(Field key) throws IOException {
		return table.getRecord(key);
	}

}
