package cppclassanalyzer.database.schema.fields;

import db.Field;

public interface FieldEnum {
	String getName();
	Class<? extends Field> getFieldClass();
	int getIndex();
}