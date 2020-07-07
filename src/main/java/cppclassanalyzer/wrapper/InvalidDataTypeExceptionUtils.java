package cppclassanalyzer.wrapper;

import ghidra.program.model.data.InvalidDataTypeException;

final class InvalidDataTypeExceptionUtils {

	private static final Thrower<RuntimeException> thrower = new Thrower<>();

	private InvalidDataTypeExceptionUtils() {
	}

	static void rethrow(InvalidDataTypeException e) {
		thrower.rethrow(e);
	}

	static <T> T throwReturn(InvalidDataTypeException e) {
		thrower.rethrow(e);
		return null;
	}

	private static final class Thrower<T extends Throwable> {

		@SuppressWarnings("unchecked")
		void rethrow(InvalidDataTypeException e) throws T {
			throw (T) e;
		}
	}

}
