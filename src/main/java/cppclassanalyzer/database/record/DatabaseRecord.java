package cppclassanalyzer.database.record;

import java.io.IOException;

import db.*;
import cppclassanalyzer.database.schema.fields.FieldEnum;

public interface DatabaseRecord<T extends FieldEnum> {
	Schema getSchema();

	DatabaseRecord<T> copy();

	byte[] getBinaryData(T type);

	boolean getBooleanValue(T type);

	byte getByteValue(T type);

	int getColumnCount();

	Field getFieldValue(T type);

	int getIntValue(T type);

	long getKey();

	Field getKeyField();

	long getLongValue(T type);

	short getShortValue(T type);

	String getStringValue(T type);

	long[] getLongArray(T type);

	int[] getIntArray(T type);

	boolean hasSameSchema(DBRecord other);

	boolean hasSameSchema(Schema schema);

	boolean isDirty();

	int length();

	void read(Buffer buf, int offset) throws IOException;

	void setBinaryData(T type, byte[] bytes);

	void setBooleanValue(T type, boolean value);

	void setByteValue(T type, byte value);

	void setFieldValue(T type, Field field);

	void setIntValue(T type, int value);

	void setLongValue(T type, long value);

	void setShortValue(T type, short value);

	void setStringValue(T type, String value);

	void setLongArray(T type, long[] values);

	void setIntArray(T type, int[] values);

	void setKey(long key);

	void setKey(Field key);

	void write(Buffer buf, int offset) throws IOException;

	DBRecord getRecord();

	public interface ByteConvertable {
		byte[] toBytes();
	}
}
