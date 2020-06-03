//@category CppClassAnalyzer
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNodeManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import cppclassanalyzer.data.vtable.AbstractVtableDB;

import db.DBHandle;

public class ResetDatabaseScript extends GhidraScript {

	private static final String TREE_TABLE_NAME =
		TypeInfoTreeNodeManager.class.getSimpleName();
	private static final String TYPE_TABLE_NAME =
		AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME;
	private static final String VTABLE_TABLE_NAME =
		AbstractVtableDB.VTABLE_TABLE_NAME;

	@Override
	public void run() throws Exception {
		DBHandle handle = ((ProgramDB) currentProgram).getDBHandle();
		if (handle.getTable(TYPE_TABLE_NAME) != null) {
			handle.deleteTable(TYPE_TABLE_NAME);
		}
		if (handle.getTable(VTABLE_TABLE_NAME) != null) {
			handle.deleteTable(VTABLE_TABLE_NAME);
		}
		if (handle.getTable(TREE_TABLE_NAME) != null) {
			handle.deleteTable(TREE_TABLE_NAME);
		}
		println("Database removed. Please restart ghidra");
	}
}