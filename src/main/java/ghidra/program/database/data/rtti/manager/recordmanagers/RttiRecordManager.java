package ghidra.program.database.data.rtti.manager.recordmanagers;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.database.map.AddressMap;

public interface RttiRecordManager<T1 extends ClassTypeInfoDB, T2 extends DatabaseObject> {

	static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	public db.Record getTypeRecord(long key);

	public db.Record getVtableRecord(long key);

	public void updateRecord(db.Record record);

	public ClassTypeInfoManager getManager();

	public T1 getType(long key);

	public T2 getVtable(long key);

	public DBObjectCache<T1> getTypeCache();

	public DBObjectCache<T2> getVtableCache();

	public T1 resolve(ClassTypeInfo type);

	public T2 resolve(Vtable vtable);
}