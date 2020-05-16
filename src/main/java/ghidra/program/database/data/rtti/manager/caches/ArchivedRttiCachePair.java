package ghidra.program.database.data.rtti.manager.caches;

import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;

public final class ArchivedRttiCachePair
	extends RttiCachePair<ArchivedClassTypeInfo, ArchivedGnuVtable> {

	public static final int DEFAULT_CACHE_SIZE = 10;

	public ArchivedRttiCachePair() {
		this(DEFAULT_CACHE_SIZE);
	}
	public ArchivedRttiCachePair(int capacity) {
		super(capacity);
	}
}