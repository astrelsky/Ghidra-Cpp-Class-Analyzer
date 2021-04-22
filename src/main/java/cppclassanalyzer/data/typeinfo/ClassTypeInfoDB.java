package cppclassanalyzer.data.typeinfo;

import java.util.Map;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.database.DatabaseObject;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.recordmanagers.ArchiveRttiRecordManager;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.data.*;

import cppclassanalyzer.database.record.ArchivedClassTypeInfoRecord;
import cppclassanalyzer.database.record.ClassTypeInfoRecord;

/**
 * A {@link DatabaseObject} implementation of a {@link ClassTypeInfo}
 */
public abstract class ClassTypeInfoDB extends DatabaseObject implements ClassTypeInfo {

	public static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	ClassTypeInfoDB(ProgramRttiRecordManager manager, ClassTypeInfoRecord record) {
		super(manager.getTypeCache(), record.getKey());
	}

	ClassTypeInfoDB(ProgramRttiRecordManager manager, long key) {
		super(manager.getTypeCache(), key);
	}

	ClassTypeInfoDB(ArchiveRttiRecordManager manager, ArchivedClassTypeInfoRecord record) {
		super(manager.getTypeCache(), record.getKey());
	}

	/**
	 * Gets the manager containing this type
	 * @return the manager containing this type
	 */
	public abstract ClassTypeInfoManager getManager();

	@Override
	public abstract ClassTypeInfoDB[] getParentModels();

	/**
	 * Gets the id for this type's class data type
	 * @return the class data type's id
	 */
	public abstract long getClassDataTypeId();

	/**
	 * Checks if this type is modifiable
	 * @return true if this type is modifiable
	 */
	public abstract boolean isModifiable();

	/**
	 * Gets a map of this types bases and offsets
	 * @return a map of bases to offsets
	 */
	public abstract Map<ClassTypeInfo, Integer> getBaseOffsets();

	/**
	 * Gets this type class data type which is appropriate for inheriting
	 * @return an inheritable form of the class data type
	 */
	public final Structure getSuperClassDataType() {
		Structure struct = getClassDataType();
		CategoryPath path = new CategoryPath(struct.getCategoryPath(), struct.getName());
		DataTypeManager dtm = struct.getDataTypeManager();
		if (!dtm.containsCategory(path)) {
			return struct;
		}
		DataType superStruct = dtm.getDataType(path, "super_"+struct.getName());
		return superStruct != null ? (Structure) superStruct : struct;
	}

	@Override
	public boolean checkIsValid() {
		return super.checkIsValid();
	}

}
