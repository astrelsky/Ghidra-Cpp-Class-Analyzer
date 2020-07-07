package cppclassanalyzer.data.manager;

import java.io.File;
import java.io.IOException;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNodeManager;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.caches.ArchivedRttiCachePair;
import cppclassanalyzer.data.manager.tables.ArchivedRttiTablePair;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.GnuClassTypeInfoDB;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Lock;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import org.apache.commons.io.FilenameUtils;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import cppclassanalyzer.database.tables.ArchivedClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.ArchivedGnuVtableDatabaseTable;
import cppclassanalyzer.database.utils.TransactionHandler;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import db.DBConstants;
import db.DBHandle;
import db.Table;
import generic.jar.ResourceFile;
import resources.ResourceManager;

// from cppclassanalyzer.data import ArchiveClassTypeInfoManager
public final class ArchiveClassTypeInfoManager extends StandAloneDataTypeManager
		implements FileArchiveClassTypeInfoManager {

	private static final Icon[] ICONS = new Icon[] {
		ResourceManager.loadImage("images/openBookGreen.png"),
		ResourceManager.loadImage("images/closedBookGreen.png")
	};

	private final File file;
	private final ClassTypeInfoManagerPlugin plugin;
	private final RttiRecordWorker worker;
	private final Lock lock;
	private final TypeInfoTreeNodeManager treeNodeManager;

	private ArchiveClassTypeInfoManager(ClassTypeInfoManagerPlugin plugin,
			File file, int openMode) throws IOException {
		super(new ResourceFile(file), openMode);
		this.plugin = plugin;
		this.file = file;
		lock = new Lock(getClass().getSimpleName());
		this.treeNodeManager = new TypeInfoTreeNodeManager(this, dbHandle);
		ArchivedClassTypeInfoDatabaseTable classTable = getClassTable();
		ArchivedGnuVtableDatabaseTable vtableTable = getVtableTable();
		if (classTable == null) {
			classTable = createClassTable();
		}
		if (vtableTable == null) {
			vtableTable = createVtableTable();
		}
		ArchivedRttiCachePair caches = new ArchivedRttiCachePair();
		ArchivedRttiTablePair tables = new ArchivedRttiTablePair(classTable, vtableTable);
		this.worker = new RttiRecordWorker(tables, caches);
		this.name = FilenameUtils.removeExtension(file.getName());
	}

	private ArchivedClassTypeInfoDatabaseTable getClassTable() {
		Table classTable = dbHandle.getTable(ArchivedClassTypeInfo.TABLE_NAME);
		if (classTable == null) {
			return null;
		}
		return new ArchivedClassTypeInfoDatabaseTable(classTable);
	}

	private ArchivedGnuVtableDatabaseTable getVtableTable() {
		Table vtableTable = dbHandle.getTable(ArchivedGnuVtable.TABLE_NAME);
		if (vtableTable == null) {
			return null;
		}
		return new ArchivedGnuVtableDatabaseTable(vtableTable);
	}

	private ArchivedClassTypeInfoDatabaseTable createClassTable() throws IOException {
		long id = dbHandle.startTransaction();
		Table classTable = dbHandle.createTable(
			ArchivedClassTypeInfo.TABLE_NAME,
			ArchivedClassTypeInfoSchema.SCHEMA,
			ArchivedClassTypeInfoSchema.INDEXED_COLUMNS);
		dbHandle.endTransaction(id, true);
		return new ArchivedClassTypeInfoDatabaseTable(classTable);
	}

	private ArchivedGnuVtableDatabaseTable createVtableTable() throws IOException {
		long id = dbHandle.startTransaction();
		Table vtableTable = dbHandle.createTable(
			ArchivedGnuVtable.TABLE_NAME,
			ArchivedGnuVtableSchema.SCHEMA,
			ArchivedGnuVtableSchema.INDEXED_COLUMNS);
		dbHandle.endTransaction(id, true);
		return new ArchivedGnuVtableDatabaseTable(vtableTable);
	}

	public static ArchiveClassTypeInfoManager createManager(ClassTypeInfoManagerPlugin plugin,
			File file) throws IOException {
		return new ArchiveClassTypeInfoManager(plugin, file, DBConstants.CREATE);
	}

	@Override
	public String getPath() {
		return file.getAbsolutePath();
	}

	@Override
	public boolean isModifiable() {
		return dbHandle.canUpdate();
	}

	public static ArchiveClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin, File file,
			boolean openForUpdate) throws IOException {
		int mode = openForUpdate ? DBConstants.UPDATE : DBConstants.READ_ONLY;
		return new ArchiveClassTypeInfoManager(plugin, file, mode);
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

	@Override
	public boolean isChanged() {
		lock.acquire();
		try {
			return dbHandle.isChanged();
		} finally {
			lock.release();
		}
	}

	@Override
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

	public ArchivedClassTypeInfo resolve(ClassTypeInfo type) {
		if (type instanceof GnuClassTypeInfoDB) {
			return resolve((GnuClassTypeInfoDB) type);
		}
		return null;
	}

	public ArchivedClassTypeInfo resolve(GnuClassTypeInfoDB type) {
		return worker.resolve(type);
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		return worker.getTypeStream();
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) {
		return worker.getType(gc);
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) {
		return worker.getType(fun);
	}

	@Override
	public ClassTypeInfoDB getType(String name, Namespace namespace) {
		return worker.getType(name, namespace);
	}

	@Override
	public ClassTypeInfoDB getType(String symbolName) {
		return worker.getType(symbolName);
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

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? ICONS[0] : ICONS[1];
	}

	@Override
	public TypeInfoTreeNodeManager getTreeNodeManager() {
		return treeNodeManager;
	}

	@Override
	public ClassTypeInfoDB getType(long key) {
		return worker.getType(key);
	}

	public static FileArchiveClassTypeInfoManager openIfManagerArchive(
			ClassTypeInfoManagerPlugin plugin, Archive archive) throws IOException {
		if (archive instanceof FileArchive) {
			try {
				ResourceFile resource = ((FileArchive) archive).getFile();
				PackedDatabase db =
					PackedDatabase.getPackedDatabase(resource, false, TaskMonitor.DUMMY);
				DBHandle handle = db.open(TaskMonitor.DUMMY);
				if (handle.getTable(ArchivedClassTypeInfo.TABLE_NAME) != null) {
					File file = resource.getFile(false);
					boolean updateable = archive.isModifiable();
					plugin.getDataTypeManagerHandler().closeArchive(archive);
					return open(plugin, file, updateable);
				}
			} catch (CancelledException e) {
			}
		}
		return null;
	}

	private void endTransaction(long id, boolean commit) {
		endTransaction((int) id, commit);
	}

	private TransactionHandler getHandler() {
		return new TransactionHandler(this::startTransaction, this::endTransaction);
	}

	private final class RttiRecordWorker extends ArchiveRttiRecordWorker {

		RttiRecordWorker(ArchivedRttiTablePair tables, ArchivedRttiCachePair caches) {
			super(ArchiveClassTypeInfoManager.this, tables, caches, getHandler());
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
		ClassTypeInfoManagerPlugin getPlugin() {
			return plugin;
		}

		@Override
		public DataTypeManager getDataTypeManager() {
			return ArchiveClassTypeInfoManager.this;
		}
	}
}
