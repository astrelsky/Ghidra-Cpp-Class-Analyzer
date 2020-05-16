package ghidra.program.database.data.rtti.typeinfo;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.manager.recordmanagers.ArchiveRttiRecordManager;
import ghidra.program.database.data.rtti.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.database.map.AddressMap;

public abstract class ClassTypeInfoDB extends DatabaseObject implements ClassTypeInfo {

	public static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	ClassTypeInfoDB(ProgramRttiRecordManager manager, db.Record record) {
		super(manager.getTypeCache(), record.getKey());
	}

	ClassTypeInfoDB(ArchiveRttiRecordManager manager, db.Record record) {
		super(manager.getTypeCache(), record.getKey());
	}

	public abstract ClassTypeInfoManager getManager();

	@Override
	public abstract ClassTypeInfoDB[] getParentModels();

}