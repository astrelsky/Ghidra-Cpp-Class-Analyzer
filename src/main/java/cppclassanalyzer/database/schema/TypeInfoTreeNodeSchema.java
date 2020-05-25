package cppclassanalyzer.database.schema;

import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields;
import db.Record;

public class TypeInfoTreeNodeSchema extends AbstractSchema<TypeInfoTreeNodeRecord> {

	private static final int VERSION = 0;
	public static final TypeInfoTreeNodeSchema SCHEMA = new TypeInfoTreeNodeSchema(VERSION);
	public static final int[] INDEXED_COLUMNS = new int[] {
		TypeInfoTreeNodeSchemaFields.SYMBOL_PATH.ordinal()
	};

	private TypeInfoTreeNodeSchema(int version) {
		super(version, "Key",
			TypeInfoTreeNodeSchemaFields.getFields(),
			TypeInfoTreeNodeSchemaFields.getFieldNames());
	}

	@Override
	public TypeInfoTreeNodeRecord getRecord(Record record) {
		return new TypeInfoTreeNodeRecord(record);
	}

}