package cppclassanalyzer.database.schema.fields;

import java.util.Arrays;

import db.*;

public enum VtableSchemaFields implements FieldEnum {

	/** Name of the Program the type originated from */
	PROGRAM_NAME(StringField.class),
	ADDRESS(LongField.class),
	CLASS(LongField.class),
	RECORDS(BinaryField.class);

	private final Class<? extends Field> fieldClass;

	VtableSchemaFields(Class<? extends Field> fieldClass) {
		this.fieldClass = fieldClass;
	}

	public static Class<?>[] getFields() {
		return Arrays.stream(values())
			.map(FieldEnum::getFieldClass)
			.toArray(Class<?>[]::new);
	}

	public static String[] getFieldNames() {
		return Arrays.stream(values())
			.map(FieldEnum::getName)
			.toArray(String[]::new);
	}


	@Override
	public String getName() {
		return name();
	}

	@Override
	public Class<? extends Field> getFieldClass() {
		return fieldClass;
	}

	@Override
	public int getIndex() {
		return ordinal();
	}
}