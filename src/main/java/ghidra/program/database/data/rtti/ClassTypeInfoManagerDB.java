package ghidra.program.database.data.rtti;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.VsCppClassBuilder;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.WindowsVtableModel;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.rtti.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.GnuClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.WindowsClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.AbstractVtableDB;
import ghidra.program.database.data.rtti.vtable.VftableDB;
import ghidra.program.database.data.rtti.vtable.VtableModelDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Lock;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.datastruct.RedBlackLongKeySet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

import db.*;
import db.util.ErrorHandler;

// man = ghidra.program.database.ClassTypeInfoManagerDB(currentProgram)
public class ClassTypeInfoManagerDB implements ManagerDB, ClassTypeInfoManager, ErrorHandler {

	private DBObjectCache<AbstractClassTypeInfoDB> classCache;
	private DBObjectCache<AbstractVtableDB> vtableCache;
	private Lock lock;
	private ProgramDB program;
	private AddressMap map;
	private Table classTable;
	private Table vtableTable;

	public ClassTypeInfoManagerDB(ProgramDB program) {
		this.program = program;
		this.map = program.getAddressMap();
		DBHandle handle = program.getDBHandle();
		classCache = new DBObjectCache<>(100);
		vtableCache = new DBObjectCache<>(100);
		lock = new Lock(getClass().getSimpleName());
		classTable = handle.getTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		vtableTable = handle.getTable(AbstractVtableDB.VTABLE_TABLE_NAME);
		try {
			if (classTable == null) {
				classTable = getNewClassTable(handle);
			}
			if (vtableTable == null) {
				vtableTable = getNewVtableTable(handle);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
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

	public long getClassKey(Address address) {
		lock.acquire();
		try {
			long addrKey = encodeAddress(address);
			long[] keys = classTable.findRecords(
				new LongField(addrKey), AbstractClassTypeInfoDB.SchemaOrdinals.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0];
			}
			if (keys.length > 1) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: duplicate ClassTypeInfo detected");
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return AddressMap.INVALID_ADDRESS_KEY;
	}

	public long getVtableKey(Address address) {
		lock.acquire();
		try {
			long addrKey = encodeAddress(address);
			long[] keys = vtableTable.findRecords(
				new LongField(addrKey), AbstractVtableDB.SchemaOrdinals.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0];
			}
			if (keys.length > 1) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: duplicate Vtable detected");
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return AddressMap.INVALID_ADDRESS_KEY;
	}

	long getKey(ClassTypeInfo type) {
		return getClassKey(type.getAddress());
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

	long getClassKey() {
		return classTable.getKey();
	}

	long getVtableKey() {
		return vtableTable.getKey();
	}

	private boolean containsClassKey(Address address) {
		lock.acquire();
		try {
			long key = getClassKey(address);
			if (key != AddressMap.INVALID_ADDRESS_KEY) {
				return classTable.hasRecord(key);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	public db.Record getClassRecord(long key) {
		lock.acquire();
		try {
			return classTable.getRecord(key);
		}
		catch (IOException e) {
			program.dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	db.Record getRecord(AbstractClassTypeInfoDB type) {
		return getClassRecord(type.getKey());
	}

	public db.Record getRecord(AbstractVtableDB vtable) {
		lock.acquire();
		try {
			return vtableTable.getRecord(vtable.getKey());
		}
		catch (IOException e) {
			program.dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	public void updateRecord(db.Record record) {
		lock.acquire();
		try {
			if (record.hasSameSchema(AbstractClassTypeInfoDB.SCHEMA)) {
				classTable.putRecord(record);
			}
			else if (record.hasSameSchema(AbstractVtableDB.SCHEMA)) {
				vtableTable.putRecord(record);
			}
			else {
				throw new AssertException("Ghidra-Cpp-Class-Analyzer: unexpected record");
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	boolean hasVtable(long key) {
		if (key == 0) {
			return false;
		}
		lock.acquire();
		try {
			return vtableTable.hasRecord(key);
		}
		catch (IOException e) {
			program.dbError(e);
			return false;
		}
		finally {
			lock.release();
		}
	}

	private boolean isGnu() {
		return GnuUtils.isGnuCompiler(getProgram());
	}

	private boolean isVs() {
		return PEUtil.canAnalyze(getProgram());
	}

	public Vtable getVtable(long key) {
		if (key == AddressMap.INVALID_ADDRESS_KEY) {
			return Vtable.NO_VTABLE;
		}
		lock.acquire();
		try {
			if (vtableTable.hasRecord(key)) {
				AbstractVtableDB vtable = vtableCache.get(key);
				if (vtable == null) {
					if (isGnu()) {
						vtable = new VtableModelDB(this, vtableCache, key);
					}
					else if (isVs()) {
						vtable = new VftableDB(this, vtableCache, key);
					}
					else {
						throw new AssertException(
							"Ghidra-Cpp-Class-Analyzer: unknown/unsupported compiler");
					}
				}
				return vtable;
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return Vtable.NO_VTABLE;
	}

	boolean containsRecord(AbstractClassTypeInfoDB type) {
		lock.acquire();
		try {
			return classTable.hasRecord(type.getKey());
		}
		catch (IOException e) {
			program.dbError(e);
			return false;
		}
		finally {
			lock.release();
		}
	}

	public boolean containsRecord(AbstractVtableDB vtable) {
		lock.acquire();
		try {
			return vtableTable.hasRecord(vtable.getKey());
		}
		catch (IOException e) {
			program.dbError(e);
			return false;
		}
		finally {
			lock.release();
		}
	}

	public AbstractClassTypeInfoDB getClass(long key) {
		lock.acquire();
		try {
			if (!classTable.hasRecord(key)) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: db doesn't contain key " + Long.toString(key));
			}
			AbstractClassTypeInfoDB type = classCache.get(key);
			if (type != null) {
				return type;
			}
			return buildType(getClassRecord(key));
		}
		catch (IOException e) {
			program.dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ProgramDB getProgram() {
		return program;
	}

	public DBLongIterator getClassRecordIterator() {
		lock.acquire();
		try {
			return classTable.longKeyIterator();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	public void deleteAll() {
		lock.acquire();
		try {
			classCache.invalidate();
			vtableCache.invalidate();
			DBHandle handle = program.getDBHandle();
			handle.deleteTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
			handle.deleteTable(AbstractVtableDB.VTABLE_TABLE_NAME);
			classTable = getNewClassTable(handle);
			vtableTable = getNewVtableTable(handle);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
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
		// TODO Auto-generated method stub

	}

	@Override
	public void invalidateCache(boolean all) {
		lock.acquire();
		classCache.invalidate();
		lock.release();
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			classTable.deleteRecords(startAddr.getOffset(), endAddr.getOffset());
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {
		lock.acquire();
		try {
			long offset = toAddr.getOffset() - fromAddr.getOffset();
			long endAddress = fromAddr.getOffset() + length;
			db.Record startRecord = classTable.getRecordAtOrAfter(fromAddr.getOffset());
			DBLongIterator iter = classTable.longKeyIterator(
				fromAddr.getOffset(), fromAddr.getOffset() + length, startRecord.getKey());

			List<Long> keys = new LinkedList<>();
			while (iter.hasNext()) {
				keys.add(iter.next());
			}

			for (Long key : keys) {
				if (key > endAddress) {
					break;
				}

				db.Record record = classTable.getRecord(key);
				record.setKey(key + offset);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private AbstractClassTypeInfoDB buildType(ClassTypeInfo type, db.Record record) {
		if (isGnu()) {
			return new GnuClassTypeInfoDB(this, classCache, type, record);
		}
		if (isVs()) {
			return new WindowsClassTypeInfoDB(this, classCache, type, record);
		}
		throw new AssertException("Ghidra-Cpp-Class-Analyzer: unknown/unsupported compiler");
	}

	private AbstractClassTypeInfoDB buildType(db.Record record) {
		if (isGnu()) {
			return new GnuClassTypeInfoDB(this, classCache, record);
		}
		if (isVs()) {
			return new WindowsClassTypeInfoDB(this, classCache, record);
		}
		throw new AssertException("Ghidra-Cpp-Class-Analyzer: unknown/unsupported compiler");
	}

	@Override
	public ClassTypeInfo getClassTypeInfo(Address address) {
		lock.acquire();
		try {
			long key = getClassKey(address);
			ClassTypeInfo type = classCache.get(key);
			if (type != null) {
				return type;
			}
			if (key != AddressMap.INVALID_ADDRESS_KEY) {
				db.Record record = getClassRecord(key);
				type = buildType(record);
			}
			else {
				db.Record record = AbstractClassTypeInfoDB.SCHEMA.createRecord(getClassKey());
				TypeInfo ti = getTypeInfo(address, false);
				if (ti instanceof ClassTypeInfo) {
					type = buildType((ClassTypeInfo) ti, record);
					classTable.putRecord(record);
				}
			}
			return type;
		}
		catch (IOException e) {
			program.dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ClassTypeInfo getClassTypeInfo(GhidraClass gc) {
		SymbolTable table = program.getSymbolTable();
		List<Symbol> symbols = table.getSymbols("typeinfo", gc);
		OptionalLong key = symbols.stream()
				.map(Symbol::getAddress)
				.mapToLong(this::encodeAddress)
				.findFirst();
		if (key.isPresent()) {
			return getClass(key.getAsLong());
		}
		return null;
	}

	@Override
	public ClassTypeInfo getClassTypeInfo(Function fun) {
		GenericCallingConvention cc = fun.getCallingConvention().getGenericCallingConvention();
		if (cc.equals(GenericCallingConvention.thiscall)) {
			return getClassTypeInfo((GhidraClass) fun.getParentNamespace());
		}
		throw new InvalidParameterException(
			String.format("Ghidra-Cpp-Class-Analyzer: %s is not within a class namespace",
				fun.getSignature(true)));
	}

	@Override
	public ClassTypeInfo getClassTypeInfo(String name) {
		return getClassTypeInfo(name, program.getGlobalNamespace());
	}

	@Override
	public ClassTypeInfo getClassTypeInfo(String name, Namespace namespace) {
		SymbolTable table = program.getSymbolTable();
		Symbol symbol = table.getClassSymbol(name, namespace);
		if (symbol != null) {
			return getClassTypeInfo((GhidraClass) symbol.getObject());
		}
		return null;
	}

	@Override
	public AbstractClassTypeInfoDB resolve(ClassTypeInfo type) {
		if (type instanceof AbstractClassTypeInfoDB) {
			return (AbstractClassTypeInfoDB) type;
		}
		lock.acquire();
		try {
			db.Record record;
			long key = getClassKey(type.getAddress());
			if (key != AddressMap.INVALID_ADDRESS_KEY) {
				return getClass(key);
			}
			else {
				record = AbstractClassTypeInfoDB.SCHEMA.createRecord(getClassKey());

				// the record must be placed in the table so that its key is seen as taken
				classTable.putRecord(record);
			}
			type = buildType(type, record);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return (AbstractClassTypeInfoDB) type;
	}

	@Override
	public Vtable resolve(Vtable vtable) {
		if (vtable instanceof AbstractVtableDB) {
			return vtable;
		}
		lock.acquire();
		try {
			db.Record record;
			long key = getVtableKey(vtable.getAddress());
			if (key != AddressMap.INVALID_ADDRESS_KEY) {
				return getVtable(key);
			}
			else {
				record = AbstractVtableDB.SCHEMA.createRecord(getVtableKey());
			}
			AbstractClassTypeInfoDB type = (AbstractClassTypeInfoDB) vtable.getTypeInfo();
			if (vtable instanceof VtableModel) {
				vtable = new VtableModelDB(this, vtableCache, (VtableModel) vtable, record);
			}
			else if (vtable instanceof WindowsVtableModel) {
				vtable = new VftableDB(this, vtableCache, (WindowsVtableModel) vtable, record);
			}
			else {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: unknown/unsupported compiler");
			}
			vtableTable.putRecord(record);
			type.setVtable(vtable);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return vtable;
	}

	@Override
	public int getClassTypeInfoCount() {
		return classTable.getRecordCount();
	}

	@Override
	public int getVtableCount() {
		return vtableTable.getRecordCount();
	}

	@Override
	public Iterable<ClassTypeInfo> getIterable(boolean reverse) {
		return () -> getClassTypeInfoStream(reverse).iterator();
	}

	@Override
	public Iterable<Vtable> getVtableIterable(boolean reverse) {
		return () -> StreamSupport.stream(getIterable(reverse).spliterator(), false)
				.map(ClassTypeInfo::getVtable)
				.filter(Vtable::isValid)
				.iterator();
	}

	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	@Override
	public Stream<ClassTypeInfo> getClassTypeInfoStream(boolean reverse) {
		long maxKey = classTable.getMaxKey();
		if (reverse) {
			return LongStream.iterate(maxKey, i -> i-1 >= 0, i -> --i)
							 .mapToObj(this::getClass);
		}
		return LongStream.iterate(0, i -> i+1 < maxKey, i -> ++i)
						 .mapToObj(this::getClass);
	}

	@Override
	public Stream<Vtable> getVtableStream() {
		// vtableTable is NOT sorted
		return getClassTypeInfoStream()
				.map(ClassTypeInfo::getVtable)
				.filter(Vtable::isValid);
	}

	private db.Record[] getClassRecords() {
		lock.acquire();
		try {
			db.Record[] keys = new db.Record[getClassTypeInfoCount()];
			RecordIterator iter = classTable.iterator();
			for (int i = 0; i < keys.length && iter.hasNext(); i++) {
				keys[i] = iter.next();
			}
			return keys;
		}
		catch (IOException e) {
			program.dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	private Stream<db.Record> getRecordStream(db.Record[] records) {
		return Arrays.stream(records).parallel();
	}

	@Override
	public void sort(TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
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
				db.Record record = getClassRecord(key);
				for (long baseKey : AbstractClassTypeInfoDB.getBaseKeys(record)) {
					monitor.checkCanceled();
					if (baseKey > key) {
						throw new AssertException(String.format(
							"%d must come before %d because it is inherited by it.",
							baseKey, key));
					}
				}
			}
			for (db.Record record : getClassRecords()) {
				monitor.checkCanceled();
				AbstractClassTypeInfoDB type = getClass(record.getKey());
				Vtable vtable = type.getVtable();
				if (vtable instanceof AbstractVtableDB) {
					AbstractVtableDB vtableDB = (AbstractVtableDB) vtable;
					vtableDB.setClassKey(record.getKey());
				}
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void rebuildTable(long[] newKeys, TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			DBHandle handle = program.getDBHandle();
			try {
				classTable.setName("old" + classTable.getName());
			}
			catch (DuplicateNameException e) {
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
			}
			catch (NoValueException e) {
				// impossible. this should not be a checked exception!
				throw new AssertException(e);
			}
			handle.deleteTable(classTable.getName());
			classTable = tmpTable;
			classCache.invalidate();
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
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
				db.Record record = getClassRecord(key);
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
		if (containsClassKey(address) && resolve) {
			return getClassTypeInfo(address);
		}
		TypeInfo type = TypeInfoFactory.getTypeInfo(program, address);
		if (type instanceof ClassTypeInfo && resolve) {
			type = resolve((ClassTypeInfo) type);
		}
		return type;
	}

	@Override
	public boolean isTypeInfo(Address address) {
		return TypeInfoFactory.isTypeInfo(program, address);
	}

	@Override
	public Structure getDataType(String typename) {
		return TypeInfoFactory.getDataType(program, typename);
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
}