package cppclassanalyzer.database.schema.fields;

import java.util.Arrays;

import db.*;

public enum ClassTypeInfoSchemaFields implements FieldEnum {

	TYPENAME(StringField.class),
	TYPEINFO_ID(ByteField.class),
	ADDRESS(LongField.class),
	DATATYPE_ID(LongField.class),
	VTABLE_SEARCHED(BooleanField.class),
	VTABLE_KEY(LongField.class),
	MODEL_DATA(BinaryField.class);

	private final Class<? extends Field> fieldClass;

	private ClassTypeInfoSchemaFields(Class<? extends Field> fieldClass) {
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