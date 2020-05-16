package ghidra.program.database.data.rtti.manager.caches;

import ghidra.program.database.data.rtti.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.AbstractVtableDB;

public final class ProgramRttiCachePair
	extends RttiCachePair<AbstractClassTypeInfoDB, AbstractVtableDB> {

	public static final int DEFAULT_CACHE_SIZE = 100;

	public ProgramRttiCachePair() {
		this(DEFAULT_CACHE_SIZE);
	}

	public ProgramRttiCachePair(int capacity) {
		super(capacity);
	}
}