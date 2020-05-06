//@category CppClassAnalyzer
import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.data.rtti.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.ArchivedDataManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;

public class DumpScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		File f = new File("C:\\Users\\astre\\Desktop\\test.gdb");
		if (f.exists()) {
			f.delete();
		}
		ClassTypeInfoManager man = ClassTypeInfoManager.getManager(currentProgram);
		ArchiveClassTypeInfoManager aman = ArchiveClassTypeInfoManager.createManager(f);
		boolean success = false;
		try {
			aman.populate(man, monitor);
			success = true;
			println(String.format("Archived %d __class_type_info", aman.getTypeCount()));
		} finally {
			aman.close();
			if (!success && f.exists()) {
				f.delete();
			}
		}
	}
}