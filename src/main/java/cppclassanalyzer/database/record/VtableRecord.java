package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.VtableSchema;
import cppclassanalyzer.database.schema.fields.VtableSchemaFields;
import db.*;

public final class VtableRecord extends AbstractDatabaseRecord<VtableSchemaFields> {

	public VtableRecord(Field key, Table table) {
		super(key, table);
	}

	public VtableRecord(Table table) {
		super(table);
	}

	public VtableRecord(DBRecord record) {
		super(record);
	}

	@Override
	public Schema getSchema() {
		return VtableSchema.SCHEMA;
	}

	@Override
	public VtableRecord copy() {
		return new VtableRecord(getRecord().copy());
	}

}
