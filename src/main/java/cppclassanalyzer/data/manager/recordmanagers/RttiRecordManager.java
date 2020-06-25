package cppclassanalyzer.data.manager.recordmanagers;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import ghidra.program.database.map.AddressMap;

import cppclassanalyzer.database.record.DatabaseRecord;

public interface RttiRecordManager<T1 extends ClassTypeInfoDB, T2 extends DatabaseObject,
		T3 extends DatabaseRecord<?>, T4 extends DatabaseRecord<?>> {

	static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	public T3 getTypeRecord(long key);

	public T4 getVtableRecord(long key);

	public void updateRecord(DatabaseRecord<?> record);

	public ClassTypeInfoManager getManager();

	public T1 getType(long key);

	public T2 getVtable(long key);

	public DBObjectCache<T1> getTypeCache();

	public DBObjectCache<T2> getVtableCache();

	public T1 resolve(ClassTypeInfo type);

	public T2 resolve(Vtable vtable);
}
