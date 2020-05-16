package ghidra.program.database.data.rtti.manager;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.ToLongFunction;
import java.util.stream.Stream;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.TypeInfoArchiveChangeRecord;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.VsCppClassBuilder;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.WindowsVtableModel;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.TypeInfoArchiveChangeRecord.ChangeType;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.database.data.rtti.manager.caches.ProgramRttiCachePair;
import ghidra.program.database.data.rtti.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.database.data.rtti.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.GnuClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.WindowsClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.AbstractVtableDB;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.database.data.rtti.vtable.VftableDB;
import ghidra.program.database.data.rtti.vtable.VtableModelDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Lock;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.datastruct.RedBlackLongKeySet;
import ghidra.util.exception.*;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import db.*;

// man = ghidra.program.database.data.rtti.ClassTypeInfoManagerDB(currentProgram)
public class ClassTypeInfoManagerDB implements ManagerDB, ProgramClassTypeInfoManager {


	private final ClassTypeInfoManagerPlugin plugin;
	private final Lock lock;
	private ProgramDB program;
	private final AddressMap map;
	private final RttiRecordWorker worker;

	public ClassTypeInfoManagerDB(ClassTypeInfoManagerPlugin plugin, ProgramDB program) {
		this.plugin = plugin;
		this.program = program;
		this.map = program.getAddressMap();
		DBHandle handle = program.getDBHandle();
		lock = new Lock(getClass().getSimpleName());
		Table classTable = handle.getTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		Table vtableTable = handle.getTable(AbstractVtableDB.VTABLE_TABLE_NAME);
		if (classTable == null || vtableTable == null) {
			try {
				long id = handle.isTransactionActive() ? -1 : handle.startTransaction();
				classTable = getNewClassTable(handle);
				vtableTable = getNewVtableTable(handle);
				if (id != -1) {
					handle.endTransaction(id, true);
				}
			} catch (IOException e) {
				program.dbError(e);
			}
		}
		ProgramRttiCachePair caches = new ProgramRttiCachePair();
		RttiTablePair tables = new RttiTablePair(classTable, vtableTable);
		this.worker = doGetWorker(tables, caches);
	}

	private RttiRecordWorker doGetWorker(RttiTablePair tables, ProgramRttiCachePair caches) {
		if (isGnu()) {
			return new GnuRttiRecordWorker(tables, caches);
		}
		if (isVs()) {
			return new WindowsRttiRecordWorker(tables, caches);
		}
		throw new AssertException("Unknown/Unsupported Compiler");
	}

	private static Table getNewClassTable(DBHandle handle) throws IOException {
		return handle.createTable(
			AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME,
			AbstractClassTypeInfoDB.SCHEMA,
			AbstractClassTypeInfoDB.INDEXED_COLUMNS);
	}

	private static Table getNewVtableTable(DBHandle handle) throws IOException {
		return handle.createTable(
			AbstractVtableDB.VTABLE_TABLE_NAME,
			AbstractVtableDB.SCHEMA,
			AbstractVtableDB.INDEXED_COLUMNS);
	}

	private int startTransaction(String msg) {
		if (program.getCurrentTransaction() == null) {
			return program.startTransaction(msg);
		}
		return -1;
	}

	private void endTransaction(int id) {
		if (id != -1) {
			program.endTransaction(id, false);
		}
	}

	@Override
	public String getName() {
		return getProgram().getName();
	}

	public long getTypeKey(Address address) {
		lock.acquire();
		try {
			long addrKey = encodeAddress(address);
			long[] keys = worker.getTables()
					.getTypeTable()
					.findRecords(
						new LongField(addrKey),
						AbstractClassTypeInfoDB.SchemaOrdinals.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0];
			}
			if (keys.length > 1) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: duplicate ClassTypeInfo detected");
			}
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
		return INVALID_KEY;
	}

	public long getVtableKey(Address address) {
		lock.acquire();
		try {
			long addrKey = encodeAddress(address);
			long[] keys = worker.getTables()
					.getVtableTable()
					.findRecords(
						new LongField(addrKey), AbstractVtableDB.SchemaOrdinals.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0];
			}
			if (keys.length > 1) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: duplicate Vtable detected");
			}
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
		return INVALID_KEY;
	}

	public Address decodeAddress(long offset) {
		return map.decodeAddress(offset);
	}

	public long encodeAddress(Address address) {
		return map.getKey(address, true);
	}

	AbstractCppClassBuilder getBuilder(ClassTypeInfo type) {
		if (GnuUtils.isGnuCompiler(program)) {
			return new GccCppClassBuilder(type);
		}
		if (PEUtil.canAnalyze(program)) {
			DataValidationOptions options = new DataValidationOptions();
			TypeDescriptorModel model =
				new TypeDescriptorModel(program, type.getAddress(), options);
			return new VsCppClassBuilder(RttiModelWrapper.getWrapper(model));
		}
		throw new AssertException("Ghidra-Cpp-Class-Analyzer: unknown program rtti");
	}

	private boolean containsClassKey(Address address) {
		lock.acquire();
		try {
			long key = getTypeKey(address);
			if (key != INVALID_KEY) {
				return worker.getTables().getTypeTable().hasRecord(key);
			}
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
		return false;
	}

	boolean hasVtable(long key) {
		if (key == 0) {
			return false;
		}
		lock.acquire();
		try {
			return worker.getTables().getVtableTable().hasRecord(key);
		} catch (IOException e) {
			program.dbError(e);
			return false;
		} finally {
			lock.release();
		}
	}

	private boolean isGnu() {
		return GnuUtils.isGnuCompiler(getProgram());
	}

	private boolean isVs() {
		return PEUtil.canAnalyze(getProgram());
	}

	public boolean containsRecord(AbstractVtableDB vtable) {
		return hasVtable(vtable.getKey());
	}

	@Override
	public ProgramDB getProgram() {
		return program;
	}

	public void deleteAll() {
		lock.acquire();
		try {
			worker.getCaches().invalidate();
			worker.getTables().deleteAll();
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// do nothing
	}

	@Override
	public void invalidateCache(boolean all) {
		lock.acquire();
		try {
			worker.getCaches().invalidate();
		} finally {
			lock.release();
		}
	}

	private LongArrayList getTypeKeys(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		return getRangedKeys(startAddr, endAddr, this::getTypeKey, monitor);
	}

	private LongArrayList getVtableKeys(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		return getRangedKeys(startAddr, endAddr, this::getVtableKey, monitor);
	}

	private LongArrayList getRangedKeys(Address startAddr, Address endAddr,
			ToLongFunction<Address> keyFinder, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			LongArrayList keys = new LongArrayList();
			Address currentAddress = startAddr;
			while (currentAddress.compareTo(endAddr) < 0) {
				monitor.checkCanceled();
				long key = keyFinder.applyAsLong(currentAddress);
				if (key != INVALID_KEY) {
					keys.add(key);
				}
				currentAddress.add(currentAddress.getPointerSize());
			}
			return keys;
		} finally {
			lock.release();
		}
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			Table table = worker.getTables().getTypeTable();
			for (long key : getTypeKeys(startAddr, endAddr, monitor)) {
				monitor.checkCanceled();
				table.deleteRecord(key);
			}
			table = worker.getTables().getVtableTable();
			for (long key : getVtableKeys(startAddr, endAddr, monitor)) {
				monitor.checkCanceled();
				table.deleteRecord(key);
			}
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {
		lock.acquire();
		try {
			Address endAddr = fromAddr.add(length);
			Table table = worker.getTables().getTypeTable();
			int ordinal = AbstractClassTypeInfoDB.SchemaOrdinals.ADDRESS.ordinal();
			for (long key : getTypeKeys(fromAddr, endAddr, monitor)) {
				monitor.checkCanceled();
				db.Record record = table.getRecord(key);
				Address addr = decodeAddress(record.getLongValue(ordinal));
				long offset = addr.subtract(fromAddr);
				record.setLongValue(ordinal, encodeAddress(toAddr.add(offset)));
			}
			table = worker.getTables().getVtableTable();
			ordinal = AbstractVtableDB.SchemaOrdinals.ADDRESS.ordinal();
			for (long key : getVtableKeys(fromAddr, endAddr, monitor)) {
				monitor.checkCanceled();
				db.Record record = table.getRecord(key);
				Address addr = decodeAddress(record.getLongValue(ordinal));
				long offset = addr.subtract(fromAddr);
				record.setLongValue(ordinal, encodeAddress(toAddr.add(offset)));
			}
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
	}

	@Override
	public ClassTypeInfoDB getType(Address address) {
		lock.acquire();
		try {
			long key = getTypeKey(address);
			if (key != INVALID_KEY) {
				return worker.getType(key);
			}
			if (!isTypeInfo(address)) {
				return null;
			}
			TypeInfo ti = getTypeInfo(address, false);
			if (ti instanceof ClassTypeInfo) {
				return worker.resolve((ClassTypeInfo) ti);
			}
			return null;
		} finally {
			lock.release();
		}
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) {
		SymbolTable table = program.getSymbolTable();
		List<Symbol> symbols = table.getSymbols("typeinfo", gc);
		OptionalLong key = symbols.stream()
				.map(Symbol::getAddress)
				.mapToLong(this::encodeAddress)
				.findFirst();
		if (key.isPresent()) {
			return worker.getType(key.getAsLong());
		}
		return null;
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) {
		GenericCallingConvention cc = fun.getCallingConvention().getGenericCallingConvention();
		if (cc.equals(GenericCallingConvention.thiscall)) {
			return getType((GhidraClass) fun.getParentNamespace());
		}
		throw new InvalidParameterException(
			String.format("Ghidra-Cpp-Class-Analyzer: %s is not within a class namespace",
				fun.getSignature(true)));
	}

	@Override
	public ClassTypeInfoDB getType(String name) {
		return getType(name, program.getGlobalNamespace());
	}

	@Override
	public ClassTypeInfoDB getType(String name, Namespace namespace) {
		SymbolTable table = program.getSymbolTable();
		Symbol symbol = table.getClassSymbol(name, namespace);
		if (symbol != null) {
			return getType((GhidraClass) symbol.getObject());
		}
		return null;
	}

	@Override
	public AbstractClassTypeInfoDB resolve(ClassTypeInfo type) {
		return (AbstractClassTypeInfoDB) worker.resolve(type);
	}

	@Override
	public Vtable resolve(Vtable vtable) {
		return (Vtable) worker.resolve(vtable);
	}

	@Override
	public AbstractClassTypeInfoDB resolve(ArchivedClassTypeInfo type) {
		Address address = type.getAddress(program);
		long key = getTypeKey(address);
		if (key != INVALID_KEY) {
			return (AbstractClassTypeInfoDB) worker.getType(key);
		}
		SymbolTable table = program.getSymbolTable();
		Symbol s = table.getExternalSymbol(type.getSymbolName());
		if (s == null) {
			// nothing to do
			return null;
		}
		ExternalManager man = program.getExternalManager();
		ExternalLocation loc = man.getExternalLocation(s);
		try {
			loc.setAddress(address);
		} catch (InvalidInputException e) {
			throw new AssertException(e);
		}
		lock.acquire();
		try {
			key = worker.getClassKey();
			db.Record record = AbstractClassTypeInfoDB.SCHEMA.createRecord(key);
			worker.updateRecord(record);
			return new GnuClassTypeInfoDB(worker, type, record);
		} finally {
			lock.release();
		}
	}

	@Override
	public Vtable resolve(ArchivedGnuVtable vtable) {
		Address address = vtable.getAddress(program);
		long key = getVtableKey(address);
		if (key != INVALID_KEY) {
			return (Vtable) worker.getVtable(key);
		}
		SymbolTable table = program.getSymbolTable();
		Symbol s = table.getExternalSymbol(vtable.getSymbolName());
		if (s == null) {
			// nothing to do
			return null;
		}
		ExternalManager man = program.getExternalManager();
		ExternalLocation loc = man.getExternalLocation(s);
		try {
			loc.setAddress(address);
		} catch (InvalidInputException e) {
			throw new AssertException(e);
		}
		lock.acquire();
		try {
			key = worker.getVtableKey();
			db.Record record = AbstractVtableDB.SCHEMA.createRecord(key);
			worker.updateRecord(record);
			return new VtableModelDB(worker, vtable, record);
		} finally {
			lock.release();
		}
	}

	@Override
	public int getTypeCount() {
		return worker.getTables().getTypeTable().getRecordCount();
	}

	@Override
	public int getVtableCount() {
		return worker.getTables().getVtableTable().getRecordCount();
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes(boolean reverse) {
		return worker.getTypes(reverse);
	}

	@Override
	public Iterable<Vtable> getVtableIterable(boolean reverse) {
		return () -> getTypeStream(reverse)
				.map(ClassTypeInfo::getVtable)
				.filter(Vtable::isValid)
				.iterator();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream(boolean reverse) {
		return worker.getTypeStream(reverse);
	}

	@Override
	public Stream<Vtable> getVtableStream() {
		// vtableTable is NOT sorted
		return getTypeStream()
			.map(ClassTypeInfo::getVtable)
			.filter(Vtable::isValid);
	}

	private db.Record[] getClassRecords() {
		lock.acquire();
		try {
			db.Record[] keys = new db.Record[getTypeCount()];
			RecordIterator iter = worker.getTables().getTypeTable().iterator();
			for (int i = 0; i < keys.length && iter.hasNext(); i++) {
				keys[i] = iter.next();
			}
			return keys;
		} catch (IOException e) {
			program.dbError(e);
			return null;
		} finally {
			lock.release();
		}
	}

	private Stream<db.Record> getRecordStream(db.Record[] records) {
		return Arrays.stream(records).parallel();
	}

	@Override
	public void findVtables(TaskMonitor monitor) throws CancelledException {
		TaskMonitor dummy = new CancelOnlyWrappingTaskMonitor(monitor);
		sort(monitor);
		monitor.initialize(getTypeCount());
		monitor.setMessage("Finding vtables");
		TypeInfoArchiveChangeRecord changeRecord = null;
		for (ClassTypeInfoDB type : getTypes(true)) {
			monitor.checkCanceled();
			type.findVtable(dummy);
			changeRecord = new TypeInfoArchiveChangeRecord(ChangeType.TYPE_UPDATED, type);
			plugin.fireArchiveChanged(changeRecord);
			monitor.incrementProgress(1);
		}
	}

	private void sort(TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			Table classTable = worker.getTables().getTypeTable();
			classTable.rebuild(monitor);
			if (classTable.getMaxKey() > Integer.MAX_VALUE) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: Unable to sort Database. Too many keys");
			}
			db.Record[] records = getClassRecords();
			ReferenceCounter[] keys = getRecordStream(records)
					.map(ReferenceCounter::new)
					.toArray(ReferenceCounter[]::new);
			for (db.Record record : records) {
				monitor.checkCanceled();
				long[] baseKeys = AbstractClassTypeInfoDB.getBaseKeys(record);
				for (long key : baseKeys) {
					keys[(int) key].referencesFrom.getAndIncrement();
				}
			}
			Arrays.parallelSort(keys);
			long[] newKeys = Arrays.stream(keys)
					.mapToLong(ReferenceCounter::getKey)
					.toArray();
			newKeys = sortByMostDerived(newKeys, monitor);
			rebuildTable(newKeys, monitor);
			for (long key = 0; key < classTable.getMaxKey(); key++) {
				monitor.checkCanceled();
				db.Record record = worker.getTypeRecord(key);
				for (long baseKey : AbstractClassTypeInfoDB.getBaseKeys(record)) {
					monitor.checkCanceled();
					if (baseKey > key) {
						throw new AssertException(String.format(
							"%d must come before %d because it is inherited by it.",
							baseKey, key));
					}
				}
			}
			TypeInfoArchiveChangeRecord changeRecord = null;
			for (db.Record record : getClassRecords()) {
				monitor.checkCanceled();
				AbstractClassTypeInfoDB type =
					(AbstractClassTypeInfoDB) worker.getType(record.getKey());
				Vtable vtable = type.getVtable();
				if (vtable instanceof AbstractVtableDB) {
					AbstractVtableDB vtableDB = (AbstractVtableDB) vtable;
					vtableDB.setClassKey(record.getKey());
				}
				changeRecord = new TypeInfoArchiveChangeRecord(ChangeType.TYPE_UPDATED, type);
				plugin.fireArchiveChanged(changeRecord);
			}
		} catch (IOException e) {
			program.dbError(e);
		} finally {
			lock.release();
		}
	}

	private void rebuildTable(long[] newKeys, TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			DBHandle handle = program.getDBHandle();
			Table classTable = worker.getTables().getTypeTable();
			try {
				classTable.setName("old" + classTable.getName());
			} catch (DuplicateNameException e) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: cannot create temporary table");
			}
			Table tmpTable = getNewClassTable(handle);
			RecordIterator iter = classTable.iterator();
			LongIntHashtable keyMap = new LongIntHashtable(newKeys.length);
			for (int i = 0; i < newKeys.length; i++) {
				monitor.checkCanceled();
				keyMap.put(newKeys[i], i);
			}
			try {
				while (iter.hasNext()) {
					monitor.checkCanceled();
					db.Record oldRecord = iter.next();
					db.Record record = oldRecord.copy();
					record.setKey(keyMap.get(record.getKey()));
					AbstractClassTypeInfoDB.updateRecord(record, keyMap);
					tmpTable.putRecord(record);
				}
			} catch (NoValueException e) {
				// impossible. this should not be a checked exception!
				throw new AssertException(e);
			}
			worker.getTables().deleteAll();
			worker.getCaches().invalidate();
			iter = tmpTable.iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				classTable.putRecord(iter.next().copy());
			}
			handle.deleteTable(tmpTable.getName());
			classTable.setName(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		} catch (IOException e) {
			program.dbError(e);
		} catch (DuplicateNameException e) {
			throw new AssertException(e);
		} finally {
			lock.release();
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
				db.Record record = worker.getTypeRecord(key);
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

	@Override
	public TypeInfo getTypeInfo(Address address) {
		return getTypeInfo(address, true);
	}

	public TypeInfo getTypeInfo(Address address, boolean resolve) {
		lock.acquire();
		try {
			if (containsClassKey(address) && resolve) {
				return getType(address);
			}
			if (!isTypeInfo(address)) {
				return null;
			}
			TypeInfo type = TypeInfoFactory.getTypeInfo(program, address);
			if (type instanceof ClassTypeInfo && resolve) {
				type = resolve((ClassTypeInfo) type);
			}
			return type;
		} finally {
			lock.release();
		}
	}

	@Override
	public boolean isTypeInfo(Address address) {
		return TypeInfoFactory.isTypeInfo(program, address);
	}

	@Override
	public Structure getDataType(String typename) {
		return TypeInfoFactory.getDataType(program, typename);
	}

	@Override
	public ClassTypeInfoDB getExternalClassTypeInfo(Address address) {
		// TODO
		return null;
	}

	private static class LongStack extends LongArrayList {

		private static final String ERROR_MSG = "Ghidra-Cpp-Class-Analyzer: failed to sort keys";

		/**
		 * Removes the object at the top of this stack and returns that object as the value of this function.
		 */
		public long pop() {
			if (isEmpty()) {
				throw new AssertException(ERROR_MSG);
			}
			return remove(size() - 1);
		}

		/**
		 * Pushes an item onto the top of this stack.
		 * @param item the object to push onto the stack.
		 */
		public long push(long item) {
			int sz = size();
			add(item);
			if (size() > sz) {
				return item;
			}
			throw new AssertException(ERROR_MSG);
		}
	}

	private static class ReferenceCounter implements Comparable<ReferenceCounter> {

		final long key;
		final long referencesTo;
		final AtomicLong referencesFrom;

		ReferenceCounter(db.Record record) {
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

	private abstract class RttiRecordWorker
		extends AbstractRttiRecordWorker<AbstractClassTypeInfoDB, AbstractVtableDB>
		implements ProgramRttiRecordManager {

		int id = -1;

		RttiRecordWorker(RttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		public final void dbError(IOException e) {
			program.dbError(e);
		}

		@Override
		public final ClassTypeInfoManagerDB getManager() {
			return ClassTypeInfoManagerDB.this;
		}

		@Override
		final void acquireLock() {
			lock.acquire();
		}

		@Override
		final void releaseLock() {
			lock.release();
		}

		@Override
		final long getTypeKey(ClassTypeInfo type) {
			return getManager().getTypeKey(type.getAddress());
		}

		@Override
		final long getVtableKey(Vtable vtable) {
			return getManager().getVtableKey(vtable.getAddress());
		}

		@Override
		public final void startTransaction(String description) {
			id = getManager().startTransaction(description);
		}

		@Override
		public final void endTransaction() {
			getManager().endTransaction(id);
			id = -1;
		}
	}

	private final class GnuRttiRecordWorker extends RttiRecordWorker {

		GnuRttiRecordWorker(RttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		GnuClassTypeInfoDB buildType(db.Record record) {
			return new GnuClassTypeInfoDB(this, record);
		}

		@Override
		GnuClassTypeInfoDB buildType(ClassTypeInfo type, db.Record record) {
			return new GnuClassTypeInfoDB(this, type, record);
		}

		@Override
		VtableModelDB buildVtable(db.Record record) {
			return new VtableModelDB(this, record);
		}

		@Override
		VtableModelDB buildVtable(Vtable vtable, db.Record record) {
			return new VtableModelDB(this, (GnuVtable) vtable, record);
		}

	}

	private final class WindowsRttiRecordWorker extends RttiRecordWorker {

		WindowsRttiRecordWorker(RttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		WindowsClassTypeInfoDB buildType(db.Record record) {
			return new WindowsClassTypeInfoDB(this, record);
		}

		@Override
		WindowsClassTypeInfoDB buildType(ClassTypeInfo type, db.Record record) {
			return new WindowsClassTypeInfoDB(this, type, record);
		}

		@Override
		VftableDB buildVtable(db.Record record) {
			return new VftableDB(this, record);
		}

		@Override
		VftableDB buildVtable(Vtable vtable, db.Record record) {
			return new VftableDB(this, (WindowsVtableModel) vtable, record);
		}

	}
}