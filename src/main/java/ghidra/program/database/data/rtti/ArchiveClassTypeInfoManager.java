package ghidra.program.database.data.rtti;

import java.io.File;
import java.io.IOException;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.typeinfo.GnuClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.data.FileBasedDataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import db.*;
import generic.jar.ResourceFile;

// from ghidra.program.database.data.rtti import ArchiveClassTypeInfoManager
public class ArchiveClassTypeInfoManager extends StandAloneDataTypeManager
	implements FileBasedDataTypeManager, ClassTypeInfoManager {

	private static final String MANGLED_TYPEINFO_PREFIX = "_ZTI";
	public final static String EXTENSION = "gcti"; // Ghidra Class Type Infos
	//private static final String CONTENT_TYPE = "ClassTypeInfoArchive";

	public static final String SUFFIX = "." + EXTENSION;
	private Table classTable;
	private Table vtableTable;
	private DBObjectCache<ArchivedClassTypeInfo> classCache;
	private DBObjectCache<ArchivedGnuVtable> vtableCache;
	private final File file;
	private final RecordManager recordManager = new RecordManager();

	private final Lock lock;
	private ArchiveClassTypeInfoManager(File file, int openMode)
			throws IOException {
		super(new ResourceFile(file), openMode);
		this.file = file;
		lock = new Lock(getClass().getSimpleName());
		classCache = new DBObjectCache<>(10);
		vtableCache = new DBObjectCache<>(10);
		classTable = dbHandle.getTable(ArchivedClassTypeInfo.TABLE_NAME);
		vtableTable = dbHandle.getTable(ArchivedGnuVtable.TABLE_NAME);
		if (classTable == null) {
			createClassTable();
		}
		if (vtableTable == null) {
			createVtableTable();
		}
	}

	private void createClassTable() throws IOException {
		long id = dbHandle.startTransaction();
		classTable = dbHandle.createTable(
			ArchivedClassTypeInfo.TABLE_NAME,
			ArchivedClassTypeInfo.SCHEMA,
			ArchivedClassTypeInfo.INDEXED_COLUMNS);
		dbHandle.endTransaction(id, true);
	}

	private void createVtableTable() throws IOException {
		long id = dbHandle.startTransaction();
		vtableTable = dbHandle.createTable(
			ArchivedGnuVtable.TABLE_NAME,
			ArchivedGnuVtable.SCHEMA,
			ArchivedGnuVtable.INDEXED_COLUMNS);
		dbHandle.endTransaction(id, true);
	}

	@Override
	public void dbError(IOException e) {
		Msg.showError(this, null, "IO ERROR", e.getMessage(), e);
	}

	public static ArchiveClassTypeInfoManager createManager(File file) throws IOException {
		return new ArchiveClassTypeInfoManager(file, DBConstants.CREATE);
	}

	public static ArchiveClassTypeInfoManager open(File file) throws IOException {
		return openFileArchive(file, false);
	}

	@Override
	public String getPath() {
		return file.getAbsolutePath();
	}

	/**
	 * Open an existing data-type file archive
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException
	 */
	public static ArchiveClassTypeInfoManager open(File file, boolean openForUpdate)
			throws IOException {
		return openFileArchive(file, openForUpdate);
	}

	/**
	 * Open an existing data-type file archive
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException
	 */
	public static ArchiveClassTypeInfoManager openFileArchive(File file,
			boolean openForUpdate) throws IOException {
		int mode = openForUpdate ? DBConstants.UPDATE : DBConstants.READ_ONLY;
		return new ArchiveClassTypeInfoManager(file, mode);
	}

	public ArchivedGnuVtable getVtable(long key) {
		lock.acquire();
		try {
			if (vtableCache.get(key) != null) {
				return vtableCache.get(key);
			}
			if (vtableTable.hasRecord(key)) {
				db.Record record = vtableTable.getRecord(key);
				return new ArchivedGnuVtable(recordManager, vtableCache, record);
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		throw new IllegalArgumentException(
			String.format("Key %d doesn't exist", key));
	}

	private void updateRecord(db.Record record) {
		if (!record.isDirty()) {
			return;
		}
		lock.acquire();
		try {
			if (record.hasSameSchema(classTable.getSchema())) {
				classTable.putRecord(record);
			}
			else if (record.hasSameSchema(vtableTable.getSchema())) {
				vtableTable.putRecord(record);
			}
			else {
				throw new IllegalArgumentException("Unknown record schema");
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
	}

	private db.Record getClassRecord(long key) {
		lock.acquire();
		try {
			if (classTable.hasRecord(key)) {
				return classTable.getRecord(key);
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		return null;
	}

	private db.Record getVtableRecord(long key) {
		lock.acquire();
		try {
			if (vtableTable.hasRecord(key)) {
				return vtableTable.getRecord(key);
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		return null;
	}

	public ArchivedClassTypeInfo getClass(long key) {
		lock.acquire();
		try {
			if (classCache.get(key) != null) {
				return classCache.get(key);
			}
			if (classTable.hasRecord(key)) {
				db.Record record = classTable.getRecord(key);
				return new ArchivedClassTypeInfo(recordManager, classCache, record);
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		throw new IllegalArgumentException(
			String.format("Key %d doesn't exist", key));
	}

	private long getClassKey(String symbolName) {
		lock.acquire();
		try {
			StringField field = new StringField(symbolName);
			long[] results = classTable.findRecords(
				field, ArchivedClassTypeInfo.SchemaOrdinals.SYMBOL_NAME.ordinal());
			if (results.length == 1) {
				return results[0];
			}
		} catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return AddressMap.INVALID_ADDRESS_KEY;
	}

	private long getClassKey() {
		lock.acquire();
		try {
			return classTable.getKey();
		}
		finally {
			lock.release();
		}
	}

	private long getClassKey(ClassTypeInfo type) {
		if (type instanceof ArchivedClassTypeInfo) {
			return ((ArchivedClassTypeInfo) type).getKey();
		}
		return getClassKey(TypeInfoUtils.getSymbolName(type));
	}

	private long getVtableKey() {
		lock.acquire();
		try {
			return vtableTable.getKey();
		}
		finally {
			lock.release();
		}
	}

	private long getVtableKey(String symbolName) {
		lock.acquire();
		try {
			StringField field = new StringField(symbolName);
			long[] results = vtableTable.findRecords(
				field, ArchivedGnuVtable.SchemaOrdinals.SYMBOL_NAME.ordinal());
			if (results.length == 1) {
				return results[0];
			}
		} catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return AddressMap.INVALID_ADDRESS_KEY;
	}

	private long getVtableKey(Vtable vtable) {
		if (vtable instanceof ArchivedGnuVtable) {
			return ((ArchivedGnuVtable) vtable).getKey();
		}
		return getVtableKey(VtableUtils.getSymbolName(vtable));
	}

	@Override
	public void close() {
		lock.acquire();
		try {
			if (dbHandle.isChanged()) {
				File tmp = new File(file.getParentFile(), file.getName()+"_tmp");
				((PackedDBHandle) dbHandle).saveAs(
					"CTIArchive", tmp.getParentFile(), tmp.getName(), null, TaskMonitor.DUMMY);
				super.close();
				file.delete();
				tmp.renameTo(file);
			} else {
				super.close();
			}
		} catch (CancelledException e) {
			throw new AssertException(e);
		} catch(IOException ioe) {
			dbError(ioe);
		} finally {
			lock.release();
		}
	}

	public ArchivedClassTypeInfo getClassTypeInfo(Relocation reloc) {
		String symbolName = reloc.getSymbolName();
		if (symbolName.isBlank()) {
			return null;
		}
		long key = getClassKey(symbolName);
		if (key != AddressMap.INVALID_ADDRESS_KEY) {
			return getClass(key);
		}
		return null;
	}

	public ArchivedClassTypeInfo resolve(ClassTypeInfo type) {
		if (type instanceof GnuClassTypeInfoDB) {
			return resolve((GnuClassTypeInfoDB) type);
		}
		return null;
	}

	public ArchivedClassTypeInfo resolve(GnuClassTypeInfoDB type) {
		long key = getClassKey(type);
		if (key != AddressMap.INVALID_ADDRESS_KEY) {
			return getClass(key);
		}
		lock.acquire();
		try {
			key = getClassKey();
			db.Record record = ArchivedClassTypeInfo.SCHEMA.createRecord(key);
			classTable.putRecord(record);
			return new ArchivedClassTypeInfo(recordManager, classCache, type, record);
		} catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	public ArchivedGnuVtable resolve(Vtable vtable) {
		long key = getVtableKey(vtable);
		if (key != AddressMap.INVALID_ADDRESS_KEY) {
			return getVtable(key);
		}
		if (!(vtable instanceof GnuVtable)) {
			return null;
		}
		lock.acquire();
		try {
			key = getVtableKey();
			db.Record record = ArchivedGnuVtable.SCHEMA.createRecord(key);
			vtableTable.putRecord(record);
			return new ArchivedGnuVtable(recordManager, vtableCache, (GnuVtable) vtable, record);
		} catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	public Iterable<ArchivedClassTypeInfo> getIterable() {
		return () -> getClassTypeInfoStream().iterator();
	}

	public Iterable<ArchivedGnuVtable> getVtableIterable() {
		return () -> getVtableStream().iterator();
	}

	public Stream<ArchivedClassTypeInfo> getClassTypeInfoStream() {
		long maxKey = classTable.getMaxKey();
		return LongStream.iterate(0, i -> i <= maxKey, i -> i + 1)
				.mapToObj(this::getClass);
	}

	public Stream<ArchivedGnuVtable> getVtableStream() {
		long maxKey = vtableTable.getMaxKey();
		return LongStream.iterate(0, i -> i <= maxKey, i -> i + 1)
				.mapToObj(this::getVtable);
	}

	@Override
	public ClassTypeInfo getType(GhidraClass gc) throws UnresolvedClassTypeInfoException {
		Program program = gc.getSymbol().getProgram();
		SymbolTable table = program.getSymbolTable();
		return table.getSymbols(TypeInfo.TYPENAME_SYMBOL_NAME, gc)
			.stream()
			.findFirst()
			.map(Symbol::getAddress)
			.map(a -> TypeInfoUtils.getTypeName(program, a))
			.map(this::getType)
			.orElseGet(() -> { return null; });
	}

	@Override
	public ClassTypeInfo getType(Function fun) throws UnresolvedClassTypeInfoException {
		Namespace ns = fun.getParentNamespace();
		if (ns instanceof GhidraClass) {
			return getType((GhidraClass) ns);
		}
		return null;
	}

	@Override
	public ClassTypeInfo getType(String name, Namespace namespace)
			throws UnresolvedClassTypeInfoException {
		Program program = namespace.getSymbol().getProgram();
		SymbolTable table = program.getSymbolTable();
		Symbol s = table.getClassSymbol(name, namespace);
		if (s != null && s.getClass() == GhidraClass.class) {
			return getType((GhidraClass) s.getObject());
		}
		return null;
	}

	@Override
	public ClassTypeInfo getType(String typeName) throws UnresolvedClassTypeInfoException {
		if (typeName.isBlank()) {
			return null;
		}
		if (typeName.startsWith(MANGLED_TYPEINFO_PREFIX)) {
			typeName = typeName.substring(MANGLED_TYPEINFO_PREFIX.length());
		}
		lock.acquire();
		try {
			db.Field f = new StringField(typeName);
			long[] keys = classTable.findRecords(
				f, ArchivedClassTypeInfo.SchemaOrdinals.TYPENAME.ordinal());
			if (keys.length == 1) {
				ArchivedClassTypeInfo type = classCache.get(keys[0]);
				if (type == null) {
					db.Record record = classTable.getRecord(keys[0]);
					type = new ArchivedClassTypeInfo(recordManager, classCache, record);
				}
				return type;
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		return null;
	}

	public void populate(ProgramClassTypeInfoManager manager) {
		try {
			populate(manager, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException(e);
		}
	}

	public void populate(ProgramClassTypeInfoManager manager, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		long id = dbHandle.startTransaction();
		try {
			monitor.initialize(manager.getTypeCount());
			monitor.setMessage("Populating Data Archive");
			for (ClassTypeInfo type : manager.getTypes()) {
				monitor.checkCanceled();
				if (!(type instanceof GnuClassTypeInfoDB)) {
					monitor.setMessage("Only GNU db are supported");
					break;
				}
				long key = classTable.getKey();
				db.Record record = ArchivedClassTypeInfo.SCHEMA.createRecord(key);
				classTable.putRecord(record);
				new ArchivedClassTypeInfo(
					recordManager, classCache, (GnuClassTypeInfoDB) type, record);
				monitor.incrementProgress(1);
			}
			dbHandle.endTransaction(id, true);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getTypeCount() {
		lock.acquire();
		try {
			return classTable.getRecordCount();
		} finally {
			lock.release();
		}
	}

	@Override
	public Iterable<ClassTypeInfo> getTypes() {
		return () -> getTypeStream().iterator();
	}

	@Override
	public Stream<ClassTypeInfo> getTypeStream() {
		long maxKey = classTable.getMaxKey();
		return LongStream.iterate(0, i -> i <= maxKey, i -> i + 1)
				.mapToObj(this::getClass);
	}

	public class RecordManager {

		private RecordManager() {
		}

		public db.Record getClassRecord(long key) {
			return ArchiveClassTypeInfoManager.this.getClassRecord(key);
		}

		public db.Record getVtableRecord(long key) {
			return ArchiveClassTypeInfoManager.this.getVtableRecord(key);
		}

		public void updateRecord(db.Record record) {
			ArchiveClassTypeInfoManager.this.updateRecord(record);
		}

		public ArchiveClassTypeInfoManager getManager() {
			return ArchiveClassTypeInfoManager.this;
		}
	}

}