package cppclassanalyzer.data.manager.caches;

import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;

public abstract class RttiCachePair<T1 extends DatabaseObject, T2 extends DatabaseObject>  {

	private final DBObjectCache<T1> classCache;
	private final DBObjectCache<T2> vtableCache;

	RttiCachePair(int capacity) {
		this.classCache = new DBObjectCache<>(capacity);
		this.vtableCache = new DBObjectCache<>(capacity);
	}

	public final DBObjectCache<T1> getTypeCache() {
		return classCache;
	}

	public final DBObjectCache<T2> getVtableCache() {
		return vtableCache;
	}

	public final void invalidate() {
		classCache.invalidate();
		vtableCache.invalidate();
	}
}