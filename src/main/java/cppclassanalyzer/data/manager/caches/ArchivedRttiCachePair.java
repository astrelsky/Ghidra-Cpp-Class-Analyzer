package cppclassanalyzer.data.manager.caches;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;

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