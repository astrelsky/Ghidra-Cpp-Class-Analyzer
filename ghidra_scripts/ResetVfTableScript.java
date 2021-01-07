//@category CppClassAnalyzer
import db.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import cppclassanalyzer.data.vtable.AbstractVtableDB;
import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;

public class ResetVfTableScript extends GhidraScript {

	private static final String TYPE_TABLE_NAME =
		AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME;
	private static final String VTABLE_TABLE_NAME =
		AbstractVtableDB.VTABLE_TABLE_NAME;

	@Override
	public void run() throws Exception {
		DBHandle handle = ((ProgramDB) currentProgram).getDBHandle();
		synchronized(handle) {
			if (handle.getTable(VTABLE_TABLE_NAME) != null) {
				handle.getTable(VTABLE_TABLE_NAME).deleteAll();
			}
			Table table = handle.getTable(TYPE_TABLE_NAME);
			if (table != null) {
				RecordIterator it = table.iterator();
				while (it.hasNext()) {
					ClassTypeInfoRecord record = new ClassTypeInfoRecord(it.next());
					record.setLongValue(ClassTypeInfoSchemaFields.VTABLE_KEY, -1);
					record.setBooleanValue(ClassTypeInfoSchemaFields.VTABLE_SEARCHED, false);
					table.putRecord(record.getRecord());
				}
			}
		}
		println("Vtables reset. Please close and reopen the program.");
	}
}
