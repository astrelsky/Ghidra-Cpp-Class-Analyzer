package cppclassanalyzer.database;

import cppclassanalyzer.database.tables.DatabaseTable;

public final class SchemaMismatchException extends RuntimeException {

	private static final long serialVersionUID = 0L;

	public SchemaMismatchException(Class<? extends DatabaseTable<?>> clazz) {
		super(generateMessage(clazz));
	}

	private static String generateMessage(Class<? extends DatabaseTable<?>> clazz) {
		return "The Schema for the " + clazz.getSimpleName() + " has been changed.\n"
		+"Please run the ResetDatabaseScript with the plugin disabled.";
	}
}
