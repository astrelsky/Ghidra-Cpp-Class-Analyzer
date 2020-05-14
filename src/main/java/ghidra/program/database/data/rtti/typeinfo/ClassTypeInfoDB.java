package ghidra.program.database.data.rtti.typeinfo;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;

public abstract class ClassTypeInfoDB extends DatabaseObject implements ClassTypeInfo {

	@SuppressWarnings("rawtypes")
	ClassTypeInfoDB(DBObjectCache cache, long key) {
		super(cache, key);
	}

	public abstract ClassTypeInfoManager getManager();

	@Override
	public abstract ClassTypeInfoDB[] getParentModels();

}