package ghidra.program.database.data.rtti.manager.recordmanagers;

import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;

public interface ArchiveRttiRecordManager extends
	RttiRecordManager<ArchivedClassTypeInfo, ArchivedGnuVtable> {
}
