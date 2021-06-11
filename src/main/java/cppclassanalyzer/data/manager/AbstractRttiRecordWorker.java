package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import cppclassanalyzer.data.manager.caches.RttiCachePair;
import cppclassanalyzer.data.manager.recordmanagers.RttiRecordManager;
import cppclassanalyzer.data.manager.tables.RttiTablePair;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;

import cppclassanalyzer.database.record.DatabaseRecord;
import cppclassanalyzer.database.schema.AbstractSchema;
import cppclassanalyzer.database.utils.TransactionHandler;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.plugin.TypeInfoArchiveChangeRecord;
import cppclassanalyzer.plugin.TypeInfoArchiveChangeRecord.ChangeType;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import db.DBRecord;
import db.util.ErrorHandler;

public abstract class AbstractRttiRecordWorker<T1 extends ClassTypeInfoDB,
		T2 extends DatabaseObject, T3 extends DatabaseRecord<?>, T4 extends DatabaseRecord<?>,
		T5 extends RttiTablePair<? extends AbstractSchema<T3>, ? extends AbstractSchema<T4>>>
		implements RttiRecordManager<T1, T2, T3, T4>, ErrorHandler {

	private final T5 tables;
	private final RttiCachePair<T1, T2> caches;
	private final TransactionHandler handler;

	AbstractRttiRecordWorker(T5 tables, RttiCachePair<T1, T2> caches, TransactionHandler handler) {
		this.tables = tables;
		this.caches = caches;
		this.handler = handler;
	}
	abstract long getTypeKey(ClassTypeInfo type);

	abstract long getVtableKey(Vtable vtable);

	abstract T1 buildType(T3 record);

	abstract T1 buildType(ClassTypeInfo type, T3 record);

	abstract T2 buildVtable(T4 record);

	abstract T2 buildVtable(Vtable vtable, T4 record);

	abstract ClassTypeInfoManagerService getPlugin();

	private T3 createTypeRecord(long key) throws IOException {
		T3 record = tables.getTypeSchema().getNewRecord(key);
		tables.getTypeTable().putRecord(record.getRecord());
		return record;
	}

	private T4 createVtableRecord(long key) throws IOException {
		T4 record = tables.getVtableSchema().getNewRecord(key);
		tables.getVtableTable().putRecord(record.getRecord());
		return record;
	}

	@Override
	public final T3 getTypeRecord(long key) {
		try {
			DBRecord record = tables.getTypeTable().getRecord(key);
			if (record != null) {
				return tables.getTypeSchema().getRecord(record);
			}
		} catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	@Override
	public final T4 getVtableRecord(long key) {
		try {
			DBRecord record = tables.getVtableTable().getRecord(key);
			if (record != null) {
				return tables.getVtableSchema().getRecord(record);
			}
		} catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	@Override
	public final void updateRecord(DatabaseRecord<?> record) {
		if (!record.isDirty()) {
			return;
		}
		try {
			handler.startTransaction("Updating Record");
			if (record.hasSameSchema(tables.getTypeSchema())) {
				tables.getTypeTable().putRecord(record.getRecord());
			} else if (record.hasSameSchema(tables.getVtableSchema())) {
				tables.getVtableTable().putRecord(record.getRecord());
			} else {
				throw new IllegalArgumentException(
					"Ghidra-Cpp-Class-Analyzer: unexpected record schema");
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			handler.endTransaction();
		}
	}

	final T5 getTables() {
		return tables;
	}

	final RttiCachePair<T1, T2> getCaches() {
		return caches;
	}

	@Override
	public final DBObjectCache<T1> getTypeCache() {
		return caches.getTypeCache();
	}

	@Override
	public final DBObjectCache<T2> getVtableCache() {
		return caches.getVtableCache();
	}

	@Override
	public final T1 resolve(ClassTypeInfo type) {
		long key = getTypeKey(type);
		if (key != INVALID_KEY) {
			return getType(key);
		}
		try {
			handler.startTransaction();
			key = getClassKey();
			try {
				T3 record = createTypeRecord(key);
				T1 typeDb = buildType(type, record);
				ClassTypeInfoManagerService service = getPlugin();
				if (service instanceof ClassTypeInfoManagerPlugin) {
					ClassTypeInfoManagerPlugin plugin = (ClassTypeInfoManagerPlugin) service;
					TypeInfoArchiveChangeRecord change =
						new TypeInfoArchiveChangeRecord(ChangeType.TYPE_ADDED, typeDb);
					plugin.managerChanged(change);
				}

				return typeDb;
			} catch (RuntimeException e) {
				getTables().getTypeTable().deleteRecord(key);
				throw e;
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			handler.endTransaction();
		}
		return null;
	}

	@Override
	public final T2 resolve(Vtable vtable) {
		long key = getVtableKey(vtable);
		if (key != INVALID_KEY) {
			return getVtable(key);
		}
		try {
			handler.startTransaction();
			key = getVtableKey();
			T4 record = createVtableRecord(key);
			return buildVtable(vtable, record);
		} catch (IOException e) {
			dbError(e);
		} finally {
			handler.endTransaction();
		}
		return null;
	}

	@Override
	public final T1 getType(long key) {
		T3 record = getTypeRecord(key);
		if (record == null) {
			return null;
		}
		T1 type = caches.getTypeCache().get(record.getRecord());
		if (type == null) {
			type = buildType(record);
		}
		return type;
	}

	@Override
	public final T2 getVtable(long key) {
		T4 record = getVtableRecord(key);
		if (record == null) {
			return null;
		}
		T2 vtable = caches.getVtableCache().get(record.getRecord());
		if (vtable == null) {
			vtable = buildVtable(record);
		}
		return vtable;
	}

	final long getClassKey() {
		return tables.getTypeTable().getKey();
	}

	final long getVtableKey() {
		return tables.getVtableTable().getKey();
	}

	final Stream<ClassTypeInfoDB> getTypeStream() {
		return getTypeStream(false);
	}

	final Stream<ClassTypeInfoDB> getTypeStream(boolean reverse) {
		long maxKey = tables.getTypeTable().getMaxKey();
		LongStream keys = reverse ? LongStream.iterate(maxKey, i -> i >= 0, i -> i - 1)
			: LongStream.rangeClosed(0, maxKey);
		return keys.filter(this::containsTypeKey)
		.mapToObj(this::getType);
	}

	final Stream<T2> getVtableStream() {
		long maxKey = tables.getVtableTable().getMaxKey();
		return LongStream.rangeClosed(0, maxKey)
			.mapToObj(this::getVtable);
	}

	final Iterable<ClassTypeInfoDB> getTypes() {
		return getTypes(false);
	}

	final Iterable<ClassTypeInfoDB> getTypes(boolean reverse) {
		return () -> getTypeStream(reverse).iterator();
	}

	private boolean containsTypeKey(long key) {
		return getType(key) != null;
	}

}
