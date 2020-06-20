package cppclassanalyzer.database.schema.fields;

import java.util.Arrays;

import db.*;

public enum TypeInfoTreeNodeSchemaFields implements FieldEnum {

	NAME(StringField.class),
	SYMBOL_PATH(StringField.class),
	TYPE_ID(ByteField.class),
	TYPE_KEY(LongField.class),
	CHILDREN_KEYS(BinaryField.class);

	private final Class<? extends Field> fieldClass;

	private TypeInfoTreeNodeSchemaFields(Class<? extends Field> fieldClass) {
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
