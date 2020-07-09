package cppclassanalyzer.data.manager.recordmanagers;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.vtable.AbstractVtableDB;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.record.VtableRecord;

// Tagging interface for generic simplification
public interface ProgramRttiRecordManager extends
		RttiRecordManager<AbstractClassTypeInfoDB, AbstractVtableDB,
			ClassTypeInfoRecord, VtableRecord> {

	AbstractClassTypeInfoDB resolve(ArchivedClassTypeInfo type);

	@Override
	public ProgramClassTypeInfoManager getManager();
}
