package cppclassanalyzer.database.tables;

import java.io.IOException;

import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import cppclassanalyzer.database.schema.TypeInfoTreeNodeSchema;
import db.Field;
import db.Table;

public class TypeInfoTreeNodeTable extends AbstractDatabaseTable<TypeInfoTreeNodeSchema> {

	public TypeInfoTreeNodeTable(Table table) {
		super(table);
	}

	@Override
	public TypeInfoTreeNodeSchema getSchema() {
		return TypeInfoTreeNodeSchema.SCHEMA;
	}

	@Override
	@SuppressWarnings("unchecked")
	public final TypeInfoTreeNodeRecord getRecord(long key) throws IOException {
		db.Record record = getRawRecord(key);
		if (record != null) {
			return TypeInfoTreeNodeSchema.SCHEMA.getRecord(record);
		}
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	public TypeInfoTreeNodeRecord getRecord(Field key) throws IOException {
		db.Record record = getRawRecord(key);
		if (record != null) {
			return getSchema().getRecord(record);
		}
		return null;
	}

}