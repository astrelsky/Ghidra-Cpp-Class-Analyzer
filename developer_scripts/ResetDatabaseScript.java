//@category CppClassAnalyzer
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.rtti.manager.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.AbstractVtableDB;

import db.DBHandle;

public class ResetDatabaseScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		ClassTypeInfoManagerDB man =
			(ClassTypeInfoManagerDB) ClassTypeInfoUtils.getManager(currentProgram);
		man.deleteAll();
		DBHandle handle = ((ProgramDB) currentProgram).getDBHandle();
		handle.deleteTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		handle.deleteTable(AbstractVtableDB.VTABLE_TABLE_NAME);
		println("Database removed. Please restart ghidra");
	}
}