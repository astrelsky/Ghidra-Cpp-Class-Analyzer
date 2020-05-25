package cppclassanalyzer.database.schema.fields;

import java.util.Arrays;

import db.*;

public enum ArchivedGnuVtableSchemaFields implements FieldEnum {

	/** Address within the external program */
	ADDRESS(LongField.class),
	MANGLED_SYMBOL(StringField.class),
	TYPE_KEY(LongField.class),
	DATA(BinaryField.class);

	private final Class<? extends Field> fieldClass;

	private ArchivedGnuVtableSchemaFields(Class<? extends Field> fieldClass) {
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