//@category CppClassAnalyzer
import java.io.File;
import java.lang.reflect.Method;
import java.util.List;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.app.script.GhidraScript;
import cppclassanalyzer.data.ArchiveClassTypeInfoManager;
import cppclassanalyzer.data.ClassTypeInfoManager;
import ghidra.program.model.data.DataTypeManager;

public class DumpScript extends GhidraScript {

	private static final List<Class<? extends TypeInfo>> TYPEINFO_CLASSES =
		List.of(
			ArrayTypeInfoModel.class,
			EnumTypeInfoModel.class,
			FunctionTypeInfoModel.class,
			FundamentalTypeInfoModel.class,
			IosFailTypeInfoModel.class,
			PBaseTypeInfoModel.class,
			PointerToMemberTypeInfoModel.class,
			PointerTypeInfoModel.class
		);

	private void resolve(Class<? extends TypeInfo> clazz) throws Exception {
		Method m = clazz.getDeclaredMethod("getDataType", DataTypeManager.class);
		m.invoke(null, currentProgram.getDataTypeManager());
	}

	@Override
	public void run() throws Exception {
		File f = new File("C:\\Users\\astre\\Desktop\\test.gdb");
		if (f.exists()) {
			f.delete();
		}
		for (Class<? extends TypeInfo> clazz : TYPEINFO_CLASSES) {
			resolve(clazz);
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