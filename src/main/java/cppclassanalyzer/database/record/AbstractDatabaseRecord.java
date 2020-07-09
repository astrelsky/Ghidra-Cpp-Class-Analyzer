package cppclassanalyzer.database.record;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import cppclassanalyzer.database.schema.fields.FieldEnum;
import db.Buffer;
import db.Field;
import db.Schema;
import db.Table;

abstract class AbstractDatabaseRecord<T extends FieldEnum> implements DatabaseRecord<T> {

	private final db.Record record;

	AbstractDatabaseRecord(Field key, Table table) {
		this.record = getSchema().createRecord(key);
	}

	AbstractDatabaseRecord(Table table) {
		long key = table.getKey();
		this.record = getSchema().createRecord(key);
	}

	AbstractDatabaseRecord(db.Record record) {
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
	public final byte[] getBinaryData(T type) {
		return record.getBinaryData(type.getIndex());
	}

	@Override
	public final boolean getBooleanValue(T type) {
		return record.getBooleanValue(type.getIndex());
	}

	@Override
	public final byte getByteValue(T type) {
		return record.getByteValue(type.getIndex());
	}

	@Override
	public final int getColumnCount() {
		return record.getColumnCount();
	}

	@Override
	public final Field getFieldValue(T type) {
		return record.getFieldValue(type.getIndex());
	}

	@Override
	public final int getIntValue(T type) {
		return record.getIntValue(type.getIndex());
	}

	@Override
	public final long getKey() {
		return record.getKey();
	}

	@Override
	public final Field getKeyField() {
		return record.getKeyField();
	}

	@Override
	public final long getLongValue(T type) {
		return record.getLongValue(type.getIndex());
	}

	@Override
	public final short getShortValue(T type) {
		return record.getShortValue(type.getIndex());
	}

	@Override
	public final String getStringValue(T type) {
		return record.getString(type.getIndex());
	}

	@Override
	public final long[] getLongArray(T type) {
		ByteBuffer buf = getBuffer(type);
		return getLongArray(buf);
	}

	@Override
	public final int[] getIntArray(T type) {
		ByteBuffer buf = getBuffer(type);
		return getIntArray(buf);
	}

	@Override
	public final int hashCode() {
		return record.hashCode();
	}

	@Override
	public final boolean hasSameSchema(db.Record other) {
		return other.hasSameSchema(getSchema());
	}

	@Override
	public final boolean hasSameSchema(Schema schema) {
		return record.hasSameSchema(schema);
	}

	@Override
	public final boolean isDirty() {
		return record.isDirty();
	}

	@Override
	public final int length() {
		return record.length();
	}

	@Override
	public final void read(Buffer buf, int offset) throws IOException {
		record.read(buf, offset);
	}

	@Override
	public final void setBinaryData(T type, byte[] bytes) {
		record.setBinaryData(type.getIndex(), bytes);
	}

	@Override
	public final void setBooleanValue(T type, boolean value) {
		record.setBooleanValue(type.getIndex(), value);
	}

	@Override
	public final void setByteValue(T type, byte value) {
		record.setByteValue(type.getIndex(), value);
	}

	@Override
	public final void setFieldValue(T type, Field field) {
		record.setField(type.getIndex(), field);
	}

	@Override
	public final void setIntValue(T type, int value) {
		record.setIntValue(type.getIndex(), value);
	}

	@Override
	public final void setKey(long key) {
		record.setKey(key);
	}

	@Override
	public final void setKey(Field key) {
		record.setKey(key);
	}

	@Override
	public final void setLongValue(T type, long value) {
		record.setLongValue(type.getIndex(), value);
	}

	@Override
	public final void setShortValue(T type, short value) {
		record.setShortValue(type.getIndex(), value);
	}

	@Override
	public final void setStringValue(T type, String value) {
		record.setString(type.getIndex(), value);
	}

	@Override
	public final void setLongArray(T type, long[] values) {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES + Long.BYTES * values.length);
		setLongArray(buf, values);
		record.setBinaryData(type.getIndex(), buf.array());
	}

	@Override
	public final void setIntArray(T type, int[] values) {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES + Integer.BYTES * values.length);
		setIntArray(buf, values);
		record.setBinaryData(type.getIndex(), buf.array());
	}

	@Override
	public final void write(Buffer buf, int offset) throws IOException {
		record.write(buf, offset);
	}

	@Override
	public final db.Record getRecord() {
		return record;
	}
}
