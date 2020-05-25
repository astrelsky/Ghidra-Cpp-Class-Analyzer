package cppclassanalyzer.data.manager.tables;

import cppclassanalyzer.database.schema.ClassTypeInfoSchema;
import cppclassanalyzer.database.schema.VtableSchema;
import cppclassanalyzer.database.tables.ClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.VtableDatabaseTable;

public final class ProgramRttiTablePair extends RttiTablePair<ClassTypeInfoSchema, VtableSchema> {

	public ProgramRttiTablePair(ClassTypeInfoDatabaseTable classTable,
			VtableDatabaseTable vtableTable) {
		super(classTable, vtableTable);
	}

}