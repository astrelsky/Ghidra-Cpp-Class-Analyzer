package ghidra.program.database.data.rtti.manager;

import java.io.File;
import java.io.IOException;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.database.data.rtti.manager.caches.ArchivedRttiCachePair;
import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.GnuClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Lock;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import org.apache.commons.io.FilenameUtils;

import db.*;
import generic.jar.ResourceFile;

// from ghidra.program.database.data.rtti import ArchiveClassTypeInfoManager
public final class ArchiveClassTypeInfoManager extends StandAloneDataTypeManager
		implements FileArchiveClassTypeInfoManager {

	private final File file;
	private final ClassTypeInfoManagerPlugin plugin;
	private final RttiRecordWorker worker;

	private final Lock lock;

	private ArchiveClassTypeInfoManager(ClassTypeInfoManagerPlugin plugin,
			File file, int openMode) throws IOException {
		super(new ResourceFile(file), openMode);
		this.plugin = plugin;
		this.file = file;
		lock = new Lock(getClass().getSimpleName());
		Table classTable = dbHandle.getTable(ArchivedClassTypeInfo.TABLE_NAME);
		Table vtableTable = dbHandle.getTable(ArchivedGnuVtable.TABLE_NAME);
		if (classTable == null) {
			classTable = createClassTable();
		}
		if (vtableTable == null) {
			vtableTable = createVtableTable();
		}
		ArchivedRttiCachePair caches = new ArchivedRttiCachePair();
		RttiTablePair tables = new RttiTablePair(classTable, vtableTable);
		this.worker = new RttiRecordWorker(tables, caches);
		this.name = FilenameUtils.removeExtension(file.getName());
	}

	private Table createClassTable() throws IOException {
		long id = dbHandle.startTransaction();
		Table classTable = dbHandle.createTable(
			ArchivedClassTypeInfo.TABLE_NAME,
			ArchivedClassTypeInfo.SCHEMA,
			ArchivedClassTypeInfo.INDEXED_COLUMNS);
		dbHandle.endTransaction(id, true);
		return classTable;
	}

	private Table createVtableTable() throws IOException {
		long id = dbHandle.startTransaction();
		Table vtableTable = dbHandle.createTable(
			ArchivedGnuVtable.TABLE_NAME,
			ArchivedGnuVtable.SCHEMA,
			ArchivedGnuVtable.INDEXED_COLUMNS);
		dbHandle.endTransaction(id, true);
		return vtableTable;
	}

	public static ArchiveClassTypeInfoManager createManager(ClassTypeInfoManagerPlugin plugin,
			File file) throws IOException {
		return new ArchiveClassTypeInfoManager(plugin, file, DBConstants.CREATE);
	}

	public static ArchiveClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin,
			File file) throws IOException {
		return open(plugin, file, false);
	}

	@Override
	public String getPath() {
		return file.getAbsolutePath();
	}

	public boolean canUpdate() {
		return dbHandle.canUpdate();
	}

	public static ArchiveClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin, File file,
			boolean openForUpdate) throws IOException {
		int mode = openForUpdate ? DBConstants.UPDATE : DBConstants.READ_ONLY;
		return new ArchiveClassTypeInfoManager(plugin, file, mode);
	}

	public ArchivedGnuVtable getVtable(long key) {
		return worker.getVtable(key);
	}

	public ArchivedClassTypeInfo getClass(long key) {
		return worker.getType(key);
	}

	@Override
	public void close() {
		lock.acquire();
		try {
			if (dbHandle.isChanged()) {
				File tmp = new File(file.getParentFile(), file.getName() + "_tmp");
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
		} catch (IOException ioe) {
			worker.dbError(ioe);
		} finally {
			lock.release();
		}
	}

	public boolean isChanged() {
		lock.acquire();
		try {
			return dbHandle.isChanged();
		} finally {
			lock.release();
		}
	}

	public void save() {
		lock.acquire();
		try {
			if (dbHandle.isChanged()) {
				((PackedDBHandle) dbHandle).save(TaskMonitor.DUMMY);
			}
		} catch (IOException e) {
			worker.dbError(e);
		} catch (CancelledException ce) {
			throw new AssertException(ce);
		} finally {
			lock.release();
		}
	}

	public ArchivedClassTypeInfo getClassTypeInfo(Relocation reloc) {
		String symbolName = reloc.getSymbolName();
		if (symbolName.isBlank()) {
			return null;
		}
		long key = worker.getTypeKey(symbolName);
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
		return worker.resolve(type);
	}

	public ArchivedGnuVtable resolve(Vtable vtable) {
		return worker.resolve(vtable);
	}

	public Iterable<ClassTypeInfoDB> getIterable() {
		return () -> getTypeStream().iterator();
	}

	public Iterable<ArchivedGnuVtable> getVtableIterable() {
		return () -> getVtableStream().iterator();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		return worker.getTypeStream();
	}

	public Stream<ArchivedGnuVtable> getVtableStream() {
		return worker.getVtableStream();
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) throws UnresolvedClassTypeInfoException {
		return worker.getType(gc);
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) throws UnresolvedClassTypeInfoException {
		return worker.getType(fun);
	}

	@Override
	public ClassTypeInfoDB getType(String name, Namespace namespace)
			throws UnresolvedClassTypeInfoException {
		return worker.getType(name, namespace);
	}

	@Override
	public ClassTypeInfoDB getType(String typeName) throws UnresolvedClassTypeInfoException {
		return worker.getType(typeName);
	}

	public void populate(ProgramClassTypeInfoManager manager) {
		try {
			populate(manager, TaskMonitor.DUMMY);
		} catch (CancelledException e) {
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
				worker.resolve(type);
				Vtable vtable = type.getVtable();
				if (Vtable.isValid(vtable)) {
					worker.resolve(vtable);
				}
				monitor.incrementProgress(1);
			}
			dbHandle.endTransaction(id, true);
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
	}

	@Override
	public int getTypeCount() {
		lock.acquire();
		try {
			return worker.getTables().getTypeTable().getRecordCount();
		} finally {
			lock.release();
		}
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes() {
		return () -> worker.getTypeStream().iterator();
	}

	private final class RttiRecordWorker extends ArchiveRttiRecordWorker {

		private long id;

		RttiRecordWorker(RttiTablePair tables, ArchivedRttiCachePair caches) {
			super(ArchiveClassTypeInfoManager.this, tables, caches);
		}

		@Override
		void acquireLock() {
			lock.acquire();
		}

		@Override
		void releaseLock() {
			lock.release();
		}

		@Override
		public void startTransaction(String description) {
			lock.acquire();
			try {
				id = dbHandle.startTransaction();
			} finally {
				lock.release();
			}
		}

		@Override
		public void endTransaction() {
			if (id != -1) {
				lock.acquire();
				try {
					dbHandle.endTransaction(id, true);
				} catch (IOException e) {
					dbError(e);
				} finally {
					lock.release();
				}
			}
		}

		@Override
		ClassTypeInfoManagerPlugin getPlugin() {
			return plugin;
		}
	}

}