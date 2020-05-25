package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.TypeInfoTreeNodeSchema;
import cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields;
import cppclassanalyzer.database.record.AbstractDatabaseRecord;

public class TypeInfoTreeNodeRecord extends AbstractDatabaseRecord<TypeInfoTreeNodeSchemaFields> {

	public static final byte ROOT_NODE = 0;
	public static final byte NAMESPACE_NODE = 1;
	public static final byte TYPEINFO_NODE = 2;
	public static final byte NESTED_NODE = 3;

	public TypeInfoTreeNodeRecord(db.Record record) {
		super(record);
	}

	@Override
	public TypeInfoTreeNodeSchema getSchema() {
		return TypeInfoTreeNodeSchema.SCHEMA;
	}

	@Override
	public DatabaseRecord<TypeInfoTreeNodeSchemaFields> copy() {
		return new TypeInfoTreeNodeRecord(getRecord().copy());
	}

}