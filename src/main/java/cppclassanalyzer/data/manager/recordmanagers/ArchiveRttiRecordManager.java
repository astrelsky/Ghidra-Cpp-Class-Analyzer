package cppclassanalyzer.data.manager.recordmanagers;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;

import cppclassanalyzer.database.record.ArchivedClassTypeInfoRecord;
import cppclassanalyzer.database.record.ArchivedGnuVtableRecord;

public interface ArchiveRttiRecordManager extends
		RttiRecordManager<ArchivedClassTypeInfo, ArchivedGnuVtable,
			ArchivedClassTypeInfoRecord, ArchivedGnuVtableRecord> {
}
