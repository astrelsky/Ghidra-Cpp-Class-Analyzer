package ghidra.program.database.data.rtti;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class DataBaseUtils {

	private DataBaseUtils() {
	}
	
	public static void putLongArray(ByteBuffer buf, long[] keys) {
		buf.putInt(keys.length);
		for (long key : keys) {
			buf.putLong(key);
		}
	}

	public static long[] getLongArray(ByteBuffer buf) {
		if (buf.array().length == 0) {
			return new long[0];
		}
		long[] keys = new long[buf.getInt()];
		for (int i = 0; i < keys.length; i++) {
			keys[i] = buf.getLong();
		}
		return keys;
	}

	public static void putIntArray(ByteBuffer buf, int[] keys) {
		buf.putInt(keys.length);
		for (int key : keys) {
			buf.putInt(key);
		}
	}

	public static int[] getIntArray(ByteBuffer buf) {
		if (buf.array().length == 0) {
			return new int[0];
		}
		int[] keys = new int[buf.getInt()];
		for (int i = 0; i < keys.length; i++) {
			keys[i] = buf.getInt();
		}
		return keys;
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