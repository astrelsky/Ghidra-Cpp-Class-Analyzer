package cppclassanalyzer.data;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

public class DataBaseUtils {

	private DataBaseUtils() {
	}

	public static void putLongArray(ByteBuffer buf, long[] keys) {
		buf.putInt(keys.length);
		for (long key : keys) {
			buf.putLong(key);
		}
	}

	public static void putLongArray(db.Record record, long[] keys, int ordinal) {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES + Long.BYTES * keys.length);
		putLongArray(buf, keys);
		record.setBinaryData(ordinal, buf.array());
	}

	public static long[] getLongArray(ByteBuffer buf) {
		int size = buf.getInt();
		return LongStream.generate(buf::getLong)
			.limit(size)
			.toArray();
	}

	public static long[] getLongArray(db.Record record, int ordinal) {
		return getLongArray(ByteBuffer.wrap(record.getBinaryData(ordinal)));
	}

	public static int[] getIntArray(db.Record record, int ordinal) {
		return getIntArray(ByteBuffer.wrap(record.getBinaryData(ordinal)));
	}

	public static void putIntArray(ByteBuffer buf, int[] keys) {
		buf.putInt(keys.length);
		for (int key : keys) {
			buf.putInt(key);
		}
	}

	public static void putIntArray(db.Record record, int[] values, int ordinal) {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES * (values.length + 1));
		putIntArray(buf, values);
		record.setBinaryData(ordinal, buf.array());
	}

	public static int[] getIntArray(ByteBuffer buf) {
		int size = buf.getInt();
		return IntStream.generate(buf::getInt)
			.limit(size)
			.toArray();
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

	public interface ByteConvertable {
		byte[] toBytes();
	}
}