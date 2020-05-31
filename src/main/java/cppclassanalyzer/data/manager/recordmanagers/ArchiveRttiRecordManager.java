package cppclassanalyzer.data.manager.recordmanagers;

import ghidra.program.model.data.DataTypeManager;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;

import cppclassanalyzer.database.record.ArchivedClassTypeInfoRecord;
import cppclassanalyzer.database.record.ArchivedGnuVtableRecord;

// Tagging interface for generic simplification
public interface ArchiveRttiRecordManager extends
		RttiRecordManager<ArchivedClassTypeInfo, ArchivedGnuVtable,
			ArchivedClassTypeInfoRecord, ArchivedGnuVtableRecord> {

	DataTypeManager getDataTypeManager();
}
