package cppclassanalyzer.data.manager.tables;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import cppclassanalyzer.database.tables.ArchivedClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.ArchivedGnuVtableDatabaseTable;

public final class ArchivedRttiTablePair extends RttiTablePair<ArchivedClassTypeInfoSchema,
		ArchivedGnuVtableSchema> {

	public ArchivedRttiTablePair(ArchivedClassTypeInfoDatabaseTable classTable,
			ArchivedGnuVtableDatabaseTable vtableTable) {
		super(classTable, vtableTable);
	}

}