package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.ToLongFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.util.importer.MessageLog;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNodeManager;
import cppclassanalyzer.vs.RttiModelWrapper;
import cppclassanalyzer.vs.VsClassTypeInfo;
import cppclassanalyzer.vs.VsVtableModel;

import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.caches.ProgramRttiCachePair;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import cppclassanalyzer.data.manager.tables.ProgramRttiTablePair;
import cppclassanalyzer.data.typeinfo.*;
import cppclassanalyzer.data.vtable.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.datastruct.RedBlackLongKeySet;
import ghidra.util.exception.*;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.record.SchemaRecordIterator;
import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.schema.ClassTypeInfoSchema;
import cppclassanalyzer.database.schema.VtableSchema;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;
import cppclassanalyzer.database.schema.fields.VtableSchemaFields;
import cppclassanalyzer.database.tables.ClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.VtableDatabaseTable;
import cppclassanalyzer.database.utils.LongStack;
import cppclassanalyzer.database.utils.TransactionHandler;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.plugin.TypeInfoArchiveChangeRecord;
import cppclassanalyzer.plugin.TypeInfoArchiveChangeRecord.ChangeType;
import db.DBHandle;
import db.LongField;
import db.RecordIterator;
import db.Table;
import resources.ResourceManager;
import util.CollectionUtils;

public class ClassTypeInfoManagerDB implements ManagerDB, ProgramClassTypeInfoManager {

	private static final Icon[] ICONS = new Icon[] {
		ResourceManager.loadImage("images/openBookRed.png"),
		ResourceManager.loadImage("images/closedBookRed.png")
	};

	private final ClassTypeInfoManagerPlugin plugin;
	private final ProgramDB program;
	private final AddressMap map;
	private final RttiRecordWorker worker;
	private final TypeInfoTreeNodeManager treeNodeManager;

	public ClassTypeInfoManagerDB(ClassTypeInfoManagerPlugin plugin, ProgramDB program) {
		this.plugin = plugin;
		this.program = program;
		this.map = program.getAddressMap();
		DBHandle handle = program.getDBHandle();
		ClassTypeInfoDatabaseTable classTable = getClassTable(handle);
		VtableDatabaseTable vtableTable = getVtableTable(handle);
		if (shouldResetDatabase(classTable, vtableTable)) {
			try {
				long id = handle.isTransactionActive() ? -1 : handle.startTransaction();
				if (classTable != null) {
					handle.deleteTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
				}
				if (vtableTable != null) {
					handle.deleteTable(AbstractVtableDB.VTABLE_TABLE_NAME);
				}
				classTable = getNewClassTable(handle);
				vtableTable = getNewVtableTable(handle);
				if (id != -1) {
					handle.endTransaction(id, true);
				}
			} catch (IOException e) {
				dbError(e);
			}
		}
		ProgramRttiCachePair caches = new ProgramRttiCachePair();
		ProgramRttiTablePair tables = new ProgramRttiTablePair(classTable, vtableTable);
		this.worker = doGetWorker(tables, caches);
		this.treeNodeManager = new TypeInfoTreeNodeManager(plugin, this);
		treeNodeManager.generateTree();
	}

	private ClassTypeInfoDatabaseTable getClassTable(DBHandle handle) {
		Table classTable = handle.getTable(AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME);
		if (classTable != null) {
			return new ClassTypeInfoDatabaseTable(classTable);
		}
		return null;
	}

	private VtableDatabaseTable getVtableTable(DBHandle handle) {
		Table vtableTable = handle.getTable(AbstractVtableDB.VTABLE_TABLE_NAME);
		if (vtableTable != null) {
			return new VtableDatabaseTable(vtableTable);
		}
		return null;
	}

	private static boolean shouldResetDatabase(ClassTypeInfoDatabaseTable classTable,
			VtableDatabaseTable vtableTable) {
		if (classTable == null || vtableTable == null) {
			return true;
		}
		if (!ClassTypeInfoSchema.SCHEMA.equals(classTable.getSchema())) {
			return true;
		}
		return !VtableSchema.SCHEMA.equals(vtableTable.getSchema());
	}

	private RttiRecordWorker doGetWorker(ProgramRttiTablePair tables, ProgramRttiCachePair caches) {
		if (isGnu()) {
			return new GnuRttiRecordWorker(tables, caches);
		}
		if (isVs()) {
			return new WindowsRttiRecordWorker(tables, caches);
		}
		throw new UnsupportedOperationException("Unknown/Unsupported Compiler");
	}

	private static ClassTypeInfoDatabaseTable getNewClassTable(DBHandle handle) throws IOException {
		Table classTable = handle.createTable(
			AbstractClassTypeInfoDB.CLASS_TYPEINFO_TABLE_NAME,
			ClassTypeInfoSchema.SCHEMA,
			ClassTypeInfoSchema.INDEXED_COLUMNS);
		return new ClassTypeInfoDatabaseTable(classTable);
	}

	private static VtableDatabaseTable getNewVtableTable(DBHandle handle) throws IOException {
		Table vtableTable = handle.createTable(
			AbstractVtableDB.VTABLE_TABLE_NAME,
			VtableSchema.SCHEMA,
			VtableSchema.INDEXED_COLUMNS);
		return new VtableDatabaseTable(vtableTable);
	}

	@Override
	public String getName() {
		return getProgram().getName();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? ICONS[0] : ICONS[1];
	}

	public long getTypeKey(Address address) {
		try {
			long addrKey = encodeAddress(address);
			long[] keys = worker.getTables()
				.getTypeTable()
				.findRecords(
					new LongField(addrKey),
					ClassTypeInfoSchemaFields.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0];
			}
			if (keys.length > 1) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: duplicate ClassTypeInfo detected");
			}
		} catch (IOException e) {
			dbError(e);
		}
		return INVALID_KEY;
	}

	public long getVtableKey(Address address) {
		try {
			long addrKey = encodeAddress(address);
			long[] keys = worker.getTables()
				.getVtableTable()
				.findRecords(
					new LongField(addrKey), VtableSchemaFields.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0];
			}
			if (keys.length > 1) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: duplicate Vtable detected");
			}
		} catch (IOException e) {
			dbError(e);
		}
		return INVALID_KEY;
	}

	public Address decodeAddress(long offset) {
		return map.decodeAddress(offset);
	}

	public long encodeAddress(Address address) {
		return map.getKey(address, true);
	}

	private boolean containsClassKey(Address address) {
		try {
			long key = getTypeKey(address);
			if (key != INVALID_KEY) {
				return worker.getTables().getTypeTable().hasRecord(key);
			}
		} catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	boolean hasVtable(long key) {
		if (key == 0) {
			return false;
		}
		try {
			return worker.getTables().getVtableTable().hasRecord(key);
		} catch (IOException e) {
			dbError(e);
			return false;
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

	@Override
	public void setProgram(ProgramDB program) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// do nothing
	}

	@Override
	public void invalidateCache(boolean all) {
		worker.getCaches().invalidate();
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
			ToLongFunction<Address> keyFinder, TaskMonitor monitor) throws CancelledException {
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
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
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
			dbError(e);
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {
		try {
			Address endAddr = fromAddr.add(length);
			Table table = worker.getTables().getTypeTable();
			int ordinal = ClassTypeInfoSchemaFields.ADDRESS.ordinal();
			for (long key : getTypeKeys(fromAddr, endAddr, monitor)) {
				monitor.checkCanceled();
				db.Record record = table.getRecord(key);
				Address addr = decodeAddress(record.getLongValue(ordinal));
				long offset = addr.subtract(fromAddr);
				record.setLongValue(ordinal, encodeAddress(toAddr.add(offset)));
			}
			table = worker.getTables().getVtableTable();
			ordinal = VtableSchemaFields.ADDRESS.ordinal();
			for (long key : getVtableKeys(fromAddr, endAddr, monitor)) {
				monitor.checkCanceled();
				db.Record record = table.getRecord(key);
				Address addr = decodeAddress(record.getLongValue(ordinal));
				long offset = addr.subtract(fromAddr);
				record.setLongValue(ordinal, encodeAddress(toAddr.add(offset)));
			}
		} catch (IOException e) {
			dbError(e);
		}
	}

	private static boolean isRtti4Model(Data data) {
		if (data == null) {
			return false;
		}
		return data.getMnemonicString().equals(VsClassTypeInfo.LOCATOR_SYMBOL_NAME);
	}

	@Override
	public ClassTypeInfoDB getType(Address address) {
		if (isVs()) {
			Data data = program.getListing().getDataAt(address);
			if (isRtti4Model(data)) {
				Rtti4Model model =
					new Rtti4Model(program, address, VsClassTypeInfo.DEFAULT_OPTIONS);
				try {
					address = model.getRtti0Address();
				} catch (InvalidDataTypeException e) {
					throw new AssertException(e);
				}
			}
		}
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
	}

	@Override
	public Vtable getVtable(Address address) {
		long key = getVtableKey(address);
		if (key == INVALID_KEY) {
			return Vtable.NO_VTABLE;
		}
		return worker.getVtable(key);
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) {
		SymbolTable table = program.getSymbolTable();
		List<Symbol> symbols = table.getSymbols("typeinfo", gc);
		if (symbols.size() == 1) {
			return getType(symbols.get(0).getAddress());
		}
		// this isn't reliable but now required for vs binaries
		DataType dt =
			VariableUtilities.findOrCreateClassStruct(gc, program.getDataTypeManager());
		return getType(dt.getUniversalID());
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) {
		if (fun.getParentNamespace().isGlobal()) {
			return null;
		}
		GenericCallingConvention cc = fun.getSignature().getGenericCallingConvention();
		if (cc.equals(GenericCallingConvention.thiscall)) {
			if (!(fun.getParentNamespace() instanceof GhidraClass)) {
				Msg.info(this, fun.getParentNamespace().getName(true)+" is not a class");
				return null;
			}
			return getType((GhidraClass) fun.getParentNamespace());
		}
		return null;
	}

	@Override
	public ClassTypeInfoDB getType(String name) {
		SymbolTable table = program.getSymbolTable();
		return CollectionUtils.asStream(table.getSymbols(name))
			.map(Symbol::getAddress)
			.map(this::getType)
			.findFirst()
			.orElse(null);
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
		if (type instanceof AbstractClassTypeInfoDB) {
			if (((AbstractClassTypeInfoDB) type).checkIsValid()) {
				return (AbstractClassTypeInfoDB) type;
			}
		}
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
		key = worker.getClassKey();
		ClassTypeInfoRecord record =
			ClassTypeInfoSchema.SCHEMA.getNewRecord(key);
		worker.updateRecord(record);
		AbstractClassTypeInfoDB result = new GnuClassTypeInfoDB(worker, type, record);
		TypeInfoArchiveChangeRecord changeRecord =
			new TypeInfoArchiveChangeRecord(ChangeType.TYPE_ADDED, result);
		plugin.managerChanged(changeRecord);
		return result;
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
		key = worker.getVtableKey();
		VtableRecord record = VtableSchema.SCHEMA.getNewRecord(key);
		worker.updateRecord(record);
		return new VtableModelDB(worker, vtable, record);
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

	@Override
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
					log.appendMsg(e.getMessage());
				}
			}
			monitor.incrementProgress(1);
		}
		treeNodeManager.getRoot().removeAll();
		treeNodeManager.generateTree();
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

	@Override
	public TypeInfo getTypeInfo(Address address) {
		return getTypeInfo(address, true);
	}

	public TypeInfo getTypeInfo(Address address, boolean resolve) {
		TypeInfo type = null;
		if (containsClassKey(address) && resolve) {
			return getType(address);
		}
		if (!isTypeInfo(address)) {
			return null;
		}
		if (isGnu()) {
			type = TypeInfoFactory.getTypeInfo(program, address);
		}
		if (isVs()) {
			TypeDescriptorModel model =
				new TypeDescriptorModel(program, address, VsClassTypeInfo.DEFAULT_OPTIONS);
			try {
				type = RttiModelWrapper.getWrapper(model, TaskMonitor.DUMMY);
			} catch (CancelledException e) {
				throw new AssertException(e);
			}
		}
		if (type instanceof ClassTypeInfo && resolve) {
			type = resolve((ClassTypeInfo) type);
		}
		return type;
	}

	@Override
	public boolean isTypeInfo(Address address) {
		if (isGnu()) {
			return TypeInfoFactory.isTypeInfo(program, address);
		}
		if (isVs()) {
			try {
				TypeDescriptorModel model =
					new TypeDescriptorModel(program, address, VsClassTypeInfo.DEFAULT_OPTIONS);
				model.validate();
				return true;
			} catch (InvalidDataTypeException e) {
				// do nothing
			}
		}
		return false;
	}

	@Override
	public Structure getDataType(String typename) {
		return TypeInfoFactory.getDataType(program, typename);
	}

	@Override
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
	public TypeInfoTreeNodeManager getTreeNodeManager() {
		return treeNodeManager;
	}

	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	@Override
	public synchronized ClassTypeInfoDB getType(long key) {
		return worker.getType(key);
	}

	@Override
	public AbstractClassTypeInfoDB getType(UniversalID id) {
		try {
			Table table = worker.getTables().getTypeTable();
			LongField field = new LongField(id.getValue());
			long[] keys =
				table.findRecords(field, ClassTypeInfoSchemaFields.DATATYPE_ID.ordinal());
			if (keys.length == 1) {
				return worker.getType(keys[0]);
			}
		} catch (IOException e) {
			dbError(e);
		}
		return null;
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

	private void endTransaction(long id, boolean commit) {
		program.endTransaction((int) id, commit);
	}

	private TransactionHandler getHandler() {
		return new TransactionHandler(program::startTransaction, this::endTransaction);
	}

	private abstract class RttiRecordWorker
			extends AbstractRttiRecordWorker<
				AbstractClassTypeInfoDB, AbstractVtableDB,
				ClassTypeInfoRecord, VtableRecord, ProgramRttiTablePair>
			implements ProgramRttiRecordManager {

		RttiRecordWorker(ProgramRttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches, getHandler());
		}

		@Override
		public final void dbError(IOException e) {
			dbError(e);
		}

		@Override
		public final ClassTypeInfoManagerDB getManager() {
			return ClassTypeInfoManagerDB.this;
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
		final ClassTypeInfoManagerPlugin getPlugin() {
			return plugin;
		}

		@Override
		public final AbstractClassTypeInfoDB resolve(ArchivedClassTypeInfo type) {
			return getManager().resolve(type);
		}
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

	private final class WindowsRttiRecordWorker extends RttiRecordWorker {

		WindowsRttiRecordWorker(ProgramRttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		VsClassTypeInfoDB buildType(ClassTypeInfoRecord record) {
			return new VsClassTypeInfoDB(this, record);
		}

		@Override
		VsClassTypeInfoDB buildType(ClassTypeInfo type, ClassTypeInfoRecord record) {
			return new VsClassTypeInfoDB(this, (VsClassTypeInfo) type, record);
		}

		@Override
		VftableDB buildVtable(VtableRecord record) {
			return new VftableDB(this, record);
		}

		@Override
		VftableDB buildVtable(Vtable vtable, VtableRecord record) {
			return new VftableDB(this, (VsVtableModel) vtable, record);
		}

	}
}
