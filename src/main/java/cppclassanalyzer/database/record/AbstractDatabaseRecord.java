package cppclassanalyzer.database.record;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import cppclassanalyzer.database.schema.fields.FieldEnum;
import db.*;

abstract class AbstractDatabaseRecord<T extends FieldEnum> implements DatabaseRecord<T> {

	private final DBRecord record;

	AbstractDatabaseRecord(Field key, Table table) {
		this.record = getSchema().createRecord(key);
	}

	AbstractDatabaseRecord(Table table) {
		long key = table.getKey();
		this.record = getSchema().createRecord(key);
	}

	AbstractDatabaseRecord(DBRecord record) {
		this.record = record;
	}

	private ByteBuffer getBuffer(T type) {
		byte[] data = record.getBinaryData(type.getIndex());
		if (data == null) {
			data = new byte[Integer.BYTES];
		}
		return ByteBuffer.wrap(data);
	}

	public static int getArraySize(int[] data) {
		return Integer.BYTES + Integer.BYTES * data.length;
	}

	public static int getArraySize(long[] data) {
		return Integer.BYTES + Long.BYTES * data.length;
	}

	public static int[] getIntArray(ByteBuffer buf) {
		int size = buf.getInt();
		return IntStream.generate(buf::getInt)
			.limit(size)
			.toArray();
	}

	public static long[] getLongArray(ByteBuffer buf) {
		int size = buf.getInt();
		return LongStream.generate(buf::getLong)
				.limit(size)
				.toArray();
	}

	public static void setIntArray(ByteBuffer buf, int[] values) {
		buf.putInt(values.length);
		for (int value : values) {
			buf.putInt(value);
		}
	}

	public static void setLongArray(ByteBuffer buf, long[] values) {
		buf.putInt(values.length);
		for (long value : values) {
			buf.putLong(value);
		}
	}

	public static void putObjectArray(ByteBuffer buf, ByteConvertable[] obj) {
		byte[][] data = Arrays.stream(obj)
			.map(ByteConvertable::toBytes)
			.toArray(byte[][]::new);
		buf.putInt(data.length);
		for (byte[] bytes : data) {
			buf.put(bytes);
		}
	}

	@Override
	public final synchronized byte[] getBinaryData(T type) {
		return record.getBinaryData(type.getIndex());
	}

	@Override
	public final synchronized boolean getBooleanValue(T type) {
		return record.getBooleanValue(type.getIndex());
	}

	@Override
	public final synchronized byte getByteValue(T type) {
		return record.getByteValue(type.getIndex());
	}

	@Override
	public final synchronized int getColumnCount() {
		return record.getColumnCount();
	}

	@Override
	public final synchronized Field getFieldValue(T type) {
		return record.getFieldValue(type.getIndex());
	}

	@Override
	public final synchronized int getIntValue(T type) {
		return record.getIntValue(type.getIndex());
	}

	@Override
	public final synchronized long getKey() {
		return record.getKey();
	}

	@Override
	public final synchronized Field getKeyField() {
		return record.getKeyField();
	}

	@Override
	public final synchronized long getLongValue(T type) {
		return record.getLongValue(type.getIndex());
	}

	@Override
	public final synchronized short getShortValue(T type) {
		return record.getShortValue(type.getIndex());
	}

	@Override
	public final synchronized String getStringValue(T type) {
		return record.getString(type.getIndex());
	}

	@Override
	public final synchronized long[] getLongArray(T type) {
		ByteBuffer buf = getBuffer(type);
		return getLongArray(buf);
	}

	@Override
	public final synchronized int[] getIntArray(T type) {
		ByteBuffer buf = getBuffer(type);
		return getIntArray(buf);
	}

	@Override
	public final synchronized int hashCode() {
		return record.hashCode();
	}

	@Override
	public final synchronized boolean hasSameSchema(DBRecord other) {
		return other.hasSameSchema(getSchema());
	}

	@Override
	public final synchronized boolean hasSameSchema(Schema schema) {
		return record.hasSameSchema(schema);
	}

	@Override
	public final synchronized boolean isDirty() {
		return record.isDirty();
	}

	@Override
	public final synchronized int length() {
		return record.length();
	}

	@Override
	public final synchronized void read(Buffer buf, int offset) throws IOException {
		record.read(buf, offset);
	}

	@Override
	public final synchronized void setBinaryData(T type, byte[] bytes) {
		record.setBinaryData(type.getIndex(), bytes);
	}

	@Override
	public final synchronized void setBooleanValue(T type, boolean value) {
		record.setBooleanValue(type.getIndex(), value);
	}

	@Override
	public final synchronized void setByteValue(T type, byte value) {
		record.setByteValue(type.getIndex(), value);
	}

	@Override
	public final synchronized void setFieldValue(T type, Field field) {
		record.setField(type.getIndex(), field);
	}

	@Override
	public final synchronized void setIntValue(T type, int value) {
		record.setIntValue(type.getIndex(), value);
	}

	@Override
	public final synchronized void setKey(long key) {
		record.setKey(key);
	}

	@Override
	public final synchronized void setKey(Field key) {
		record.setKey(key);
	}

	@Override
	public final synchronized void setLongValue(T type, long value) {
		record.setLongValue(type.getIndex(), value);
	}

	@Override
	public final synchronized void setShortValue(T type, short value) {
		record.setShortValue(type.getIndex(), value);
	}

	@Override
	public final synchronized void setStringValue(T type, String value) {
		record.setString(type.getIndex(), value);
	}

	@Override
	public final synchronized void setLongArray(T type, long[] values) {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES + Long.BYTES * values.length);
		setLongArray(buf, values);
		record.setBinaryData(type.getIndex(), buf.array());
	}

	@Override
	public final synchronized void setIntArray(T type, int[] values) {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES + Integer.BYTES * values.length);
		setIntArray(buf, values);
		record.setBinaryData(type.getIndex(), buf.array());
	}

	@Override
	public final synchronized void write(Buffer buf, int offset) throws IOException {
		record.write(buf, offset);
	}

	@Override
	public final DBRecord getRecord() {
		return record;
	}
}
