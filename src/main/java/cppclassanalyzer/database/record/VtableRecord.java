package cppclassanalyzer.database.record;

import cppclassanalyzer.database.schema.VtableSchema;
import cppclassanalyzer.database.schema.fields.VtableSchemaFields;
import db.Field;
import db.Schema;
import db.Table;

public final class VtableRecord extends AbstractDatabaseRecord<VtableSchemaFields> {

	public VtableRecord(Field key, Table table) {
		super(key, table);
	}

	public VtableRecord(Table table) {
		super(table);
	}

	public VtableRecord(db.DBRecord record) {
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
