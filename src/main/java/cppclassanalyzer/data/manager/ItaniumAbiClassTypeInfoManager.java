package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.datastruct.RedBlackLongKeySet;
import ghidra.util.exception.*;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.manager.caches.ProgramRttiCachePair;
import cppclassanalyzer.data.manager.tables.ProgramRttiTablePair;
import cppclassanalyzer.data.typeinfo.*;
import cppclassanalyzer.data.vtable.AbstractVtableDB;
import cppclassanalyzer.data.vtable.VtableModelDB;
import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.record.SchemaRecordIterator;
import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;
import cppclassanalyzer.database.tables.ClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.utils.LongStack;
import cppclassanalyzer.scanner.ItaniumAbiRttiScanner;
import cppclassanalyzer.scanner.RttiScanner;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import db.*;

public final class ItaniumAbiClassTypeInfoManager extends ClassTypeInfoManagerDB {

	private ItaniumAbiRttiScanner scanner;

	public ItaniumAbiClassTypeInfoManager(ClassTypeInfoManagerService plugin, ProgramDB program) {
		super(plugin, program);
	}

	protected final ItaniumAbiRttiScanner getScanner() {
		if (scanner == null) {
			this.scanner = (ItaniumAbiRttiScanner) RttiScanner.getScanner(program);
		}
		return scanner;
	}

	@Override
	public TypeInfo getTypeInfo(Address address, boolean resolve) {
		TypeInfo ti = super.getTypeInfo(address, resolve);
		if (ti == null) {
			ti = getScanner().getTypeInfo(address);
		}
		if (ti instanceof ClassTypeInfo && resolve) {
			ti = resolve((ClassTypeInfo) ti);
		}
		return ti;
	}

	@Override
	public boolean isTypeInfo(Address address) {
		return getScanner().isTypeInfo(address);
	}

	public ClassTypeInfoDB getExternalClassTypeInfo(Address address) {
		String mangled = Arrays.stream(program.getSymbolTable().getSymbols(address))
			.map(Symbol::getName)
			.filter(s -> s.startsWith("_ZTI"))
			.filter(s -> !s.contains("@"))
			.findFirst()
			.orElse(null);
		if (mangled != null) {
			ArchivedClassTypeInfo type = plugin.getExternalClassTypeInfo(program, mangled);
			if (type != null) {
				return resolve(type);
			}
		}
		return null;
	}

	@Override
	protected GnuRttiRecordWorker getWorker(ProgramRttiTablePair tables,
			ProgramRttiCachePair caches) {
		return new GnuRttiRecordWorker(tables, caches);
	}

	private ClassTypeInfoRecord[] getClassRecords() {
		try {
			ClassTypeInfoRecord[] keys = new ClassTypeInfoRecord[getTypeCount()];
			RecordIterator iter = worker.getTables().getTypeTable().iterator();
			for (int i = 0; i < keys.length && iter.hasNext(); i++) {
				keys[i] = new ClassTypeInfoRecord(iter.next());
			}
			return keys;
		} catch (IOException e) {
			dbError(e);
			return null;
		}
	}

	private Stream<ClassTypeInfoRecord> getRecordStream(ClassTypeInfoRecord[] records) {
		return Arrays.stream(records)
			.parallel();
	}

	public void findVtables(TaskMonitor monitor, MessageLog log) throws CancelledException {
		TaskMonitor dummy = new CancelOnlyWrappingTaskMonitor(monitor);
		sort(monitor);
		monitor.initialize(getTypeCount());
		monitor.setMessage("Finding vtables");
		for (ClassTypeInfoDB type : getTypes(true)) {
			monitor.checkCanceled();
			try {
				type.findVtable(dummy);
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				if (log != null) {
					log.appendException(e);
				}
			}
			monitor.incrementProgress(1);
		}
		if (treeNodeManager != null) {
			treeNodeManager.getRoot().removeAll();
			treeNodeManager.generateTree();
		}
	}

	private boolean isValidRecord(ClassTypeInfoRecord record) {
		try {
			AbstractClassTypeInfoDB.getBaseCount(record);
			return true;
		} catch (Exception e) {
			// record is incomplete and will be removed
		}
		return false;
	}

	private void sort(TaskMonitor monitor) throws CancelledException {
		try {
			Table classTable = worker.getTables().getTypeTable();
			classTable.rebuild(monitor);
			if (classTable.getMaxKey() > Integer.MAX_VALUE) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: Unable to sort Database. Too many keys");
			}
			ClassTypeInfoRecord[] records = getClassRecords();
			Map<Long, ReferenceCounter> keys = getRecordStream(records)
				.filter(this::isValidRecord)
				.map(ReferenceCounter::new)
				.collect(Collectors.toMap(ReferenceCounter::getKey, r -> r));
			for (ClassTypeInfoRecord record : records) {
				monitor.checkCanceled();
				if (keys.containsKey(record.getKey())) {
					long[] baseKeys = AbstractClassTypeInfoDB.getBaseKeys(record);
					for (long key : baseKeys) {
						keys.get(key).referencesFrom.getAndIncrement();
					}
				}
			}
			long[] newKeys = keys.values()
				.parallelStream()
				.sorted()
				.mapToLong(ReferenceCounter::getKey)
				.toArray();
			newKeys = sortByMostDerived(newKeys, monitor);
			rebuildTable(newKeys, monitor);
			for (long key = 0; key < classTable.getMaxKey(); key++) {
				monitor.checkCanceled();
				ClassTypeInfoRecord record = worker.getTypeRecord(key);
				for (long baseKey : AbstractClassTypeInfoDB.getBaseKeys(record)) {
					monitor.checkCanceled();
					if (baseKey > key) {
						throw new AssertException(String.format(
							"%d must come before %d because it is inherited by it.",
							baseKey, key));
					}
				}
			}
			for (ClassTypeInfoRecord record : getClassRecords()) {
				monitor.checkCanceled();
				AbstractClassTypeInfoDB type =
					(AbstractClassTypeInfoDB) worker.getType(record.getKey());
				Vtable vtable = type.getVtable();
				if (vtable instanceof AbstractVtableDB) {
					AbstractVtableDB vtableDB = (AbstractVtableDB) vtable;
					vtableDB.setClassKey(record.getKey());
				}
			}
		} catch (IOException e) {
			dbError(e);
		}
	}


	private void rebuildTable(long[] newKeys, TaskMonitor monitor) throws CancelledException {
		try {
			DBHandle handle = program.getDBHandle();
			Table classTable = worker.getTables().getTypeTable();
			try {
				classTable.setName("old" + classTable.getName());
			} catch (DuplicateNameException e) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: cannot create temporary table");
			}
			ClassTypeInfoDatabaseTable tmpTable = getNewClassTable(handle);
			SchemaRecordIterator<ClassTypeInfoRecord> iter =
				new SchemaRecordIterator<>(classTable.iterator(), ClassTypeInfoRecord::new);
			LongIntHashtable keyMap = new LongIntHashtable(newKeys.length);
			for (int i = 0; i < newKeys.length; i++) {
				monitor.checkCanceled();
				keyMap.put(newKeys[i], i);
			}
			try {
				while (iter.hasNext()) {
					monitor.checkCanceled();
					ClassTypeInfoRecord oldRecord = iter.next();
					if (!keyMap.contains(oldRecord.getKey())) {
						continue;
					}
					ClassTypeInfoRecord record = oldRecord.copy();
					record.setKey(keyMap.get(record.getKey()));
					if (record.getBooleanValue(ClassTypeInfoSchemaFields.VTABLE_SEARCHED)) {
						// since the vtable table will be removed
						// this information must be cleared if present
						record.setBooleanValue(ClassTypeInfoSchemaFields.VTABLE_SEARCHED, false);
						record.setLongValue(ClassTypeInfoSchemaFields.VTABLE_KEY, INVALID_KEY);
					}
					AbstractClassTypeInfoDB.updateRecord(record, keyMap);
					tmpTable.getTable().putRecord(record.getRecord());
				}
			} catch (NoValueException e) {
				// impossible. this should not be a checked exception!
				throw new AssertException(e);
			}
			worker.getTables().deleteAll();
			worker.getCaches().invalidate();
			iter = new SchemaRecordIterator<>(
				tmpTable.getTable().iterator(), ClassTypeInfoRecord::new);
			while (iter.hasNext()) {
				monitor.checkCanceled();
				classTable.putRecord(iter.next().copy().getRecord());
			}
			handle.deleteTable(tmpTable.getName());
			classTable.setName(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		} catch (IOException e) {
			dbError(e);
		} catch (DuplicateNameException e) {
			throw new AssertException(e);
		}
	}

	private long[] sortByMostDerived(long[] oldKeys, TaskMonitor monitor)
			throws CancelledException {
		// cannot reuse old keys due to risk of overrunning the position of 'oldKey'
		long[] newKeys = new long[oldKeys.length];
		RedBlackLongKeySet processed = new RedBlackLongKeySet();
		LongStack stack = new LongStack();
		int index = 0;
		for (long oldKey : oldKeys) {
			monitor.checkCanceled();
			stack.push(oldKey);
			while (!stack.isEmpty()) {
				monitor.checkCanceled();
				long key = stack.pop();
				if (processed.containsKey(key)) {
					continue;
				}
				ClassTypeInfoRecord record = worker.getTypeRecord(key);
				boolean dirty = false;
				for (long base : AbstractClassTypeInfoDB.getBaseKeys(record)) {
					monitor.checkCanceled();
					if (!processed.containsKey(base)) {
						if (!dirty) {
							stack.push(key);
						}
						dirty = true;
						stack.push(base);
					}
				}
				if (!dirty) {
					processed.put(key);
					newKeys[index++] = key;
				}
			}
		}
		return newKeys;
	}

	private final class GnuRttiRecordWorker extends RttiRecordWorker {

		GnuRttiRecordWorker(ProgramRttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		GnuClassTypeInfoDB buildType(ClassTypeInfoRecord record) {
			return new GnuClassTypeInfoDB(this, record);
		}

		@Override
		GnuClassTypeInfoDB buildType(ClassTypeInfo type, ClassTypeInfoRecord record) {
			return new GnuClassTypeInfoDB(this, type, record);
		}

		@Override
		VtableModelDB buildVtable(VtableRecord record) {
			return new VtableModelDB(this, record);
		}

		@Override
		VtableModelDB buildVtable(Vtable vtable, VtableRecord record) {
			return new VtableModelDB(this, (GnuVtable) vtable, record);
		}

	}

	private static class ReferenceCounter implements Comparable<ReferenceCounter> {

		final long key;
		final long referencesTo;
		final AtomicLong referencesFrom;

		ReferenceCounter(ClassTypeInfoRecord record) {
			key = record.getKey();
			referencesTo = AbstractClassTypeInfoDB.getBaseCount(record);
			referencesFrom = new AtomicLong();
		}

		public long getKey() {
			return key;
		}

		@Override
		public int compareTo(ReferenceCounter o) {
			long tFrom = referencesFrom.get();
			long oFrom = o.referencesFrom.get();
			if (tFrom < oFrom) {
				return -1;
			}
			if (tFrom > oFrom) {
				return 1;
			}
			if (referencesTo < o.referencesTo) {
				return -1;
			}
			if (referencesTo > o.referencesTo) {
				return 1;
			}
			return 0;
		}
	}

}
