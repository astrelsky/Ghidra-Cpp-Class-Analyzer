package cppclassanalyzer.database.record;

import java.io.IOException;
import java.util.function.Function;

import cppclassanalyzer.database.schema.fields.FieldEnum;

import db.*;

public class SchemaRecordIterator<T extends DatabaseRecord<? extends FieldEnum>>  {

	private final RecordIterator iter;
	private final Function<DBRecord, T> constructor;

	public SchemaRecordIterator(RecordIterator iter, Function<DBRecord, T> constructor) {
		this.iter = iter;
		this.constructor = constructor;
	}

	public boolean hasNext() throws IOException {
		return iter.hasNext();
	}

	public boolean hasPrevious() throws IOException {
		return iter.hasPrevious();
	}

	public T next() throws IOException {
		return constructor.apply(iter.next());
	}

	public T previous() throws IOException {
		return constructor.apply(iter.previous());
	}

	public boolean delete() throws IOException {
		return iter.delete();
	}
}
