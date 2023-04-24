package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.*;
import java.util.function.ToLongFunction;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNodeManager;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import db.*;

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
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.database.schema.ClassTypeInfoSchema;
import cppclassanalyzer.database.schema.VtableSchema;
import cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields;
import cppclassanalyzer.database.schema.fields.VtableSchemaFields;
import cppclassanalyzer.database.tables.ClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.VtableDatabaseTable;
import cppclassanalyzer.database.utils.TransactionHandler;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.plugin.TypeInfoArchiveChangeRecord;
import cppclassanalyzer.plugin.TypeInfoArchiveChangeRecord.ChangeType;
import resources.ResourceManager;
import util.CollectionUtils;

public abstract class ClassTypeInfoManagerDB implements ManagerDB, ProgramClassTypeInfoManager {

	private static final Icon[] ICONS = new Icon[] {
		ResourceManager.loadImage("images/openBookRed.png"),
		ResourceManager.loadImage("images/closedBookRed.png")
	};

	private final AddressMap map;
	protected final ClassTypeInfoManagerService plugin;
	protected final ProgramDB program;
	protected final RttiRecordWorker worker;
	protected final TypeInfoTreeNodeManager treeNodeManager;

	protected ClassTypeInfoManagerDB(ClassTypeInfoManagerService service, ProgramDB program) {
		this.plugin = service;
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
		this.worker = getWorker(tables, caches);
		if (service instanceof ClassTypeInfoManagerPlugin) {
			ClassTypeInfoManagerPlugin plugin = (ClassTypeInfoManagerPlugin) service;
			this.treeNodeManager = new TypeInfoTreeNodeManager(plugin, this);
			treeNodeManager.generateTree();
		} else {
			this.treeNodeManager = null;
		}
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

	protected abstract RttiRecordWorker getWorker(
		ProgramRttiTablePair tables, ProgramRttiCachePair caches);

	protected static ClassTypeInfoDatabaseTable getNewClassTable(DBHandle handle) throws IOException {
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
	public final String getName() {
		return getProgram().getName();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? ICONS[0] : ICONS[1];
	}

	public final long getTypeKey(Address address) {
		try {
			long addrKey = encodeAddress(address);
			Field[] keys = worker.getTables()
				.getTypeTable()
				.findRecords(
					new LongField(addrKey),
					ClassTypeInfoSchemaFields.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0].getLongValue();
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

	public final long getVtableKey(Address address) {
		try {
			long addrKey = encodeAddress(address);
			Field[] keys = worker.getTables()
				.getVtableTable()
				.findRecords(
					new LongField(addrKey), VtableSchemaFields.ADDRESS.ordinal());
			if (keys.length == 1) {
				return keys[0].getLongValue();
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

	public final Address decodeAddress(long offset) {
		return map.decodeAddress(offset);
	}

	public final long encodeAddress(Address address) {
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

	public final boolean containsRecord(AbstractVtableDB vtable) {
		return hasVtable(vtable.getKey());
	}

	@Override
	public final ProgramDB getProgram() {
		return program;
	}

	@Override
	public final void setProgram(ProgramDB program) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// do nothing
	}

	@Override
	public final void invalidateCache(boolean all) {
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
			monitor.checkCancelled();
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
				monitor.checkCancelled();
				table.deleteRecord(key);
			}
			table = worker.getTables().getVtableTable();
			for (long key : getVtableKeys(startAddr, endAddr, monitor)) {
				monitor.checkCancelled();
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
				monitor.checkCancelled();
				DBRecord record = table.getRecord(key);
				Address addr = decodeAddress(record.getLongValue(ordinal));
				long offset = addr.subtract(fromAddr);
				record.setLongValue(ordinal, encodeAddress(toAddr.add(offset)));
			}
			table = worker.getTables().getVtableTable();
			ordinal = VtableSchemaFields.ADDRESS.ordinal();
			for (long key : getVtableKeys(fromAddr, endAddr, monitor)) {
				monitor.checkCancelled();
				DBRecord record = table.getRecord(key);
				Address addr = decodeAddress(record.getLongValue(ordinal));
				long offset = addr.subtract(fromAddr);
				record.setLongValue(ordinal, encodeAddress(toAddr.add(offset)));
			}
		} catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public ClassTypeInfoDB getType(Address address) {
		long key = getTypeKey(address);
		if (key != INVALID_KEY) {
			return worker.getType(key);
		}
		if (!isTypeInfo(address)) {
			return null;
		}
		return (ClassTypeInfoDB) getTypeInfo(address, true);
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
		return null;
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) {
		if (fun.getParentNamespace().isGlobal()) {
			return null;
		}
		String cc = fun.getSignature().getCallingConventionName();
		if (cc.equals(ClassTypeInfoUtils.THISCALL)) {
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
		if (plugin instanceof ClassTypeInfoManagerPlugin) {
			((ClassTypeInfoManagerPlugin) plugin).managerChanged(changeRecord);
		}
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

	@Override
	public TypeInfo getTypeInfo(Address address) {
		return getTypeInfo(address, true);
	}

	public TypeInfo getTypeInfo(Address address, boolean resolve) {
		if (containsClassKey(address) && resolve) {
			return getType(address);
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
			Field[] keys =
				table.findRecords(field, ClassTypeInfoSchemaFields.DATATYPE_ID.ordinal());
			if (keys.length == 1) {
				return worker.getType(keys[0].getLongValue());
			}
		} catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	@Override
	public void dispose() {
		if (treeNodeManager != null) {
			treeNodeManager.dispose();
		}
	}

	private void endTransaction(long id, boolean commit) {
		program.endTransaction((int) id, commit);
	}

	private TransactionHandler getHandler() {
		return new TransactionHandler(program::startTransaction, this::endTransaction);
	}

	protected abstract class RttiRecordWorker
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
		final ClassTypeInfoManagerService getPlugin() {
			return plugin;
		}

		@Override
		public final AbstractClassTypeInfoDB resolve(ArchivedClassTypeInfo type) {
			return getManager().resolve(type);
		}
	}
}
