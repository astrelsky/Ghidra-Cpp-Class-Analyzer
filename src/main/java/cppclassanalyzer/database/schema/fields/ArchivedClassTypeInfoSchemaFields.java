package cppclassanalyzer.database.schema.fields;

import java.util.Arrays;

import db.*;

public enum ArchivedClassTypeInfoSchemaFields implements FieldEnum {

	/** Name of the Program the type originated from */
	PROGRAM_NAME(StringField.class),
	TYPENAME(StringField.class),
	/** Address within the external program */
	ADDRESS(LongField.class),
	MANGLED_SYMBOL(StringField.class),
	CLASS_ID(ByteField.class),
	DATATYPE_ID(LongField.class),
	SUPER_DATATYPE_ID(LongField.class),
	VTABLE_KEY(LongField.class),
	BASE_KEYS(BinaryField.class),
	NON_VIRTUAL_BASE_KEYS(BinaryField.class),
	VIRTUAL_BASE_KEYS(BinaryField.class),
	BASE_OFFSETS(BinaryField.class);

	private final Class<? extends Field> fieldClass;

	private ArchivedClassTypeInfoSchemaFields(Class<? extends Field> fieldClass) {
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