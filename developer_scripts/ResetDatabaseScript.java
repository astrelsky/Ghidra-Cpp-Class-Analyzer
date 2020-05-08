//@category CppClassAnalyzer
import ghidra.app.script.GhidraScript;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;

public class ResetDatabaseScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		ClassTypeInfoManagerDB man =
			(ClassTypeInfoManagerDB) ClassTypeInfoManager.getManager(currentProgram);
		man.resetDatabase();
	}
}