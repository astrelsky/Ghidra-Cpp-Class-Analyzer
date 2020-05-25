package cppclassanalyzer.data.manager.caches;

import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import cppclassanalyzer.data.vtable.AbstractVtableDB;

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