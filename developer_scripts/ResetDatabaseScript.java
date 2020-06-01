//@category CppClassAnalyzer
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import cppclassanalyzer.data.vtable.AbstractVtableDB;

import db.DBHandle;

public class ResetDatabaseScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		DBHandle handle = ((ProgramDB) currentProgram).getDBHandle();
		handle.deleteTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		handle.deleteTable(AbstractVtableDB.VTABLE_TABLE_NAME);
		println("Database removed. Please restart ghidra");
	}
}