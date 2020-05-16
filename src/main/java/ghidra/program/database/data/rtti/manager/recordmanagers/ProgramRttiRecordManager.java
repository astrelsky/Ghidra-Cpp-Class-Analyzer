package ghidra.program.database.data.rtti.manager.recordmanagers;

import ghidra.program.database.data.rtti.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.AbstractVtableDB;

public interface ProgramRttiRecordManager extends
		RttiRecordManager<AbstractClassTypeInfoDB, AbstractVtableDB> {
}
