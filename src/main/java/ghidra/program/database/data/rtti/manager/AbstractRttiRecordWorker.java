package ghidra.program.database.data.rtti.manager;

import java.io.IOException;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.manager.caches.RttiCachePair;
import ghidra.program.database.data.rtti.manager.recordmanagers.RttiRecordManager;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;

import db.Record;
import db.Schema;
import db.util.ErrorHandler;

public abstract class AbstractRttiRecordWorker<T1 extends ClassTypeInfoDB,
		T2 extends DatabaseObject> implements RttiRecordManager<T1, T2>, ErrorHandler {

	private final RttiTablePair tables;
	private final RttiCachePair<T1, T2> caches;
	private final Schema typeSchema;
	private final Schema vtableSchema;

	AbstractRttiRecordWorker(RttiTablePair tables, RttiCachePair<T1, T2> caches) {
		this.tables = tables;
		this.caches = caches;
		this.typeSchema = tables.getTypeTable().getSchema();
		this.vtableSchema = tables.getVtableTable().getSchema();
	}

	abstract void acquireLock();

	abstract void releaseLock();

	final void startTransaction() {
		startTransaction(null);
	}

	abstract void startTransaction(String description);
	abstract void endTransaction();

	abstract long getTypeKey(ClassTypeInfo type);

	abstract long getVtableKey(Vtable vtable);

	abstract T1 buildType(db.Record record);

	abstract T1 buildType(ClassTypeInfo type, db.Record record);

	abstract T2 buildVtable(db.Record record);

	abstract T2 buildVtable(Vtable vtable, db.Record record);

	@Override
	public db.Record getTypeRecord(long key) {
		acquireLock();
		try {
			return tables.getTypeTable().getRecord(key);
		} catch (IOException e) {
			dbError(e);
		} finally {
			releaseLock();
		}
		return null;
	}

	@Override
	public db.Record getVtableRecord(long key) {
		acquireLock();
		try {
			return tables.getVtableTable().getRecord(key);
		} catch (IOException e) {
			dbError(e);
		} finally {
			releaseLock();
		}
		return null;
	}

	@Override
	public void updateRecord(Record record) {
		if (!record.isDirty()) {
			return;
		}
		acquireLock();
		try {
			startTransaction("Updating Record");
			if (record.hasSameSchema(typeSchema)) {
				tables.getTypeTable().putRecord(record);
			} else if (record.hasSameSchema(vtableSchema)) {
				tables.getVtableTable().putRecord(record);
			} else {
				throw new IllegalArgumentException(
					"Ghidra-Cpp-Class-Analyzer: unexpected record schema");
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			endTransaction();
			releaseLock();
		}
	}

	RttiTablePair getTables() {
		return tables;
	}

	RttiCachePair<T1, T2> getCaches() {
		return caches;
	}

	@Override
	public DBObjectCache<T1> getTypeCache() {
		return caches.getTypeCache();
	}

	@Override
	public DBObjectCache<T2> getVtableCache() {
		return caches.getVtableCache();
	}

	@Override
	public T1 resolve(ClassTypeInfo type) {
		long key = getTypeKey(type);
		if (key != INVALID_KEY) {
			return getType(key);
		}
		acquireLock();
		try {
			startTransaction();
			key = getClassKey();
			db.Record record = typeSchema.createRecord(key);
			tables.getTypeTable().putRecord(record);
			return buildType(type, record);
		} catch (IOException e) {
			dbError(e);
		} finally {
			endTransaction();
			releaseLock();
		}
		return null;
	}

	@Override
	public T2 resolve(Vtable vtable) {
		long key = getVtableKey(vtable);
		if (key != INVALID_KEY) {
			return getVtable(key);
		}
		if (!(vtable instanceof GnuVtable)) {
			return null;
		}
		acquireLock();
		try {
			startTransaction();
			key = getVtableKey();
			db.Record record = vtableSchema.createRecord(key);
			tables.getVtableTable().putRecord(record);
			return buildVtable(vtable, record);
		} catch (IOException e) {
			dbError(e);
		} finally {
			endTransaction();
			releaseLock();
		}
		return null;
	}

	@Override
	public T1 getType(long key) {
		acquireLock();
		try {
			db.Record record = getTypeRecord(key);
			if (record == null) {
				return null;
			}
			T1 type = caches.getTypeCache().get(record);
			if (type == null) {
				type = buildType(record);
			}
			return type;
		} finally {
			releaseLock();
		}
	}

	@Override
	public T2 getVtable(long key) {
		acquireLock();
		try {
			db.Record record = getVtableRecord(key);
			if (record == null) {
				return null;
			}
			T2 vtable = caches.getVtableCache().get(record);
			if (vtable == null) {
				vtable = buildVtable(record);
			}
			return vtable;
		} finally {
			releaseLock();
		}
	}

	long getClassKey() {
		acquireLock();
		try {
			return tables.getTypeTable().getKey();
		} finally {
			releaseLock();
		}
	}

	long getVtableKey() {
		acquireLock();
		try {
			return tables.getVtableTable().getKey();
		} finally {
			releaseLock();
		}
	}

	final Stream<ClassTypeInfoDB> getTypeStream() {
		return getTypeStream(false);
	}

	final Stream<ClassTypeInfoDB> getTypeStream(boolean reverse) {
		long maxKey = tables.getTypeTable().getMaxKey();
		if (reverse) {
			return LongStream.iterate(maxKey, i -> i >= 0, i -> i - 1)
				.mapToObj(this::getType);
		}
		return LongStream.iterate(0, i -> i <= maxKey, i -> i + 1)
			.mapToObj(this::getType);
	}

	final Stream<T2> getVtableStream() {
		long maxKey = tables.getVtableTable().getMaxKey();
		return LongStream.iterate(0, i -> i <= maxKey, i -> i + 1)
			.mapToObj(this::getVtable);
	}

	final Iterable<ClassTypeInfoDB> getTypes() {
		return getTypes(false);
	}

	final Iterable<ClassTypeInfoDB> getTypes(boolean reverse) {
		return () -> getTypeStream(reverse).iterator();
	}
}