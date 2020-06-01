package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNodeManager;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.database.data.ProjectDataTypeManager;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.tables.ArchivedRttiTablePair;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Lock;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import cppclassanalyzer.database.tables.ArchivedClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.ArchivedGnuVtableDatabaseTable;
import db.DBConstants;
import db.DBHandle;
import db.RecordIterator;
import db.Schema;
import db.StringField;
import db.Table;
import resources.ResourceManager;

public final class ProjectClassTypeInfoManager extends ProjectDataTypeManager
		implements FileArchiveClassTypeInfoManager {

	private static final Icon[] ICONS = new Icon[] {
		ResourceManager.loadImage("images/openBookBlue.png"),
		ResourceManager.loadImage("images/closedBookBlue.png")
	};

	private static final Schema SCHEMA = new Schema(
		0,
		"key",
		new Class<?>[] { StringField.class, StringField.class, StringField.class },
		new String[] { "Name", "TypeTable", "VtableTable" });

	private final ClassTypeInfoManagerPlugin plugin;
	private final ProjectArchive archive;
	private final LibraryMap libMap;
	private final TypeInfoTreeNodeManager treeNodeManager;

	private ProjectClassTypeInfoManager(ClassTypeInfoManagerPlugin plugin, ProjectArchive archive)
			throws CancelledException, VersionException, IOException {
		super(getDBHandle(archive), DBConstants.UPDATE, getDB(archive),
			getLock(archive), TaskMonitor.DUMMY);
		this.archive = archive;
		this.plugin = plugin;
		setDataTypeArchive(getDB(archive));
		this.libMap = new LibraryMap();
		this.treeNodeManager = new TypeInfoTreeNodeManager(this, getDBHandle(archive));
	}

	private static DataTypeArchiveDB getDB(ProjectArchive archive) {
		return (DataTypeArchiveDB) archive.getDomainObject();
	}

	private static DBHandle getDBHandle(ProjectArchive archive) {
		return getDB(archive).getDBHandle();
	}

	private static Lock getLock(ProjectArchive archive) {
		return getDB(archive).getLock();
	}

	public static ProjectClassTypeInfoManager createManager(ClassTypeInfoManagerPlugin plugin,
			ProjectArchive archive) throws IOException {
		try {
			return new ProjectClassTypeInfoManager(plugin, archive);
		} catch (VersionException | CancelledException e) {
			throw new AssertException(e);
		}
	}

	public static ProjectClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin,
			ProjectArchive archive) throws IOException {
		try {
			return new ProjectClassTypeInfoManager(plugin, archive);
		} catch (VersionException | CancelledException e) {
			throw new AssertException(e);
		}
	}

	private ArchivedClassTypeInfoDatabaseTable getClassTable(String name)
			throws IOException {
		acquireLock();
		try {
			return new ArchivedClassTypeInfoDatabaseTable(dbHandle.getTable(name));
		} finally {
			releaseLock();
		}
	}

	private ArchivedGnuVtableDatabaseTable getVtableTable(String name)
			throws IOException {
		acquireLock();
		try {
			return new ArchivedGnuVtableDatabaseTable(dbHandle.getTable(name));
		} finally {
			releaseLock();
		}
	}

	private ArchivedClassTypeInfoDatabaseTable createClassTable(String name) throws IOException {
		acquireLock();
		try {
			long id = dbHandle.startTransaction();
			Table classTable = dbHandle.createTable(
				name + " " + ArchivedClassTypeInfo.TABLE_NAME,
				ArchivedClassTypeInfoSchema.SCHEMA,
				ArchivedClassTypeInfoSchema.INDEXED_COLUMNS);
			dbHandle.endTransaction(id, true);
			return new ArchivedClassTypeInfoDatabaseTable(classTable);
		} finally {
			releaseLock();
		}
	}

	private ArchivedGnuVtableDatabaseTable createVtableTable(String name) throws IOException {
		acquireLock();
		try {
			long id = dbHandle.startTransaction();
			Table vtableTable = dbHandle.createTable(
				name + " " + ArchivedGnuVtable.TABLE_NAME,
				ArchivedGnuVtableSchema.SCHEMA,
				ArchivedGnuVtableSchema.INDEXED_COLUMNS);
			dbHandle.endTransaction(id, true);
			return new ArchivedGnuVtableDatabaseTable(vtableTable);
		} finally {
			releaseLock();
		}
	}

	private void checkForManager(Program program) throws UnresolvedClassTypeInfoException {
		acquireLock();
		try {
			if (!libMap.containsKey(program.getName())) {
				throw new UnresolvedClassTypeInfoException(program);
			}
		} finally {
			releaseLock();
		}
	}

	private LibraryClassTypeInfoManager getManager(String name) {
		acquireLock();
		try {
			if (!(libMap.containsKey(name))) {
				ArchivedClassTypeInfoDatabaseTable classTable = createClassTable(name);
				ArchivedGnuVtableDatabaseTable vtableTable = createVtableTable(name);
				ArchivedRttiTablePair pair = new ArchivedRttiTablePair(classTable, vtableTable);
				LibraryClassTypeInfoManager manager =
					new LibraryClassTypeInfoManager(this, pair, dbHandle, name);
				libMap.put(name, manager);
			}
			return libMap.get(name);
		} catch (IOException e) {
			dbError(e);
		} finally {
			releaseLock();
		}
		return null;
	}

	@Override
	public ClassTypeInfoDB resolve(ClassTypeInfo type) {
		String name = null;
		if (type instanceof ClassTypeInfoDB) {
			ClassTypeInfoManager manager = ((ClassTypeInfoDB) type).getManager();
			if (manager instanceof ProgramClassTypeInfoManager) {
				name = ((ProgramClassTypeInfoManager) manager).getName();
			} else {
				name = ((ArchivedClassTypeInfo) type).getProgramName();
			}
		} else {
			name = type.getGhidraClass().getSymbol().getProgram().getName();
		}
		return getManager(name).resolve(type);
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) throws UnresolvedClassTypeInfoException {
		Program program = gc.getSymbol().getProgram();
		checkForManager(program);
		return getManager(program.getName()).getType(gc);
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) throws UnresolvedClassTypeInfoException {
		Program program = fun.getSymbol().getProgram();
		checkForManager(program);
		return getManager(program.getName()).getType(fun);
	}

	@Override
	public ClassTypeInfoDB getType(String name, Namespace namespace)
			throws UnresolvedClassTypeInfoException {
		Program program = namespace.getSymbol().getProgram();
		checkForManager(program);
		return getManager(program.getName()).getType(name, namespace);
	}

	@Override
	public ClassTypeInfoDB getType(String symbolName) throws UnresolvedClassTypeInfoException {
		acquireLock();
		try {
			for (LibraryClassTypeInfoManager manager : libMap.values()) {
				ClassTypeInfoDB type = manager.getType(symbolName);
				if (type != null) {
					return type;
				}
			}
			String msg =
				"Unable to locate an archived ClassTypeInfo with symbol name " + symbolName;
			throw new UnresolvedClassTypeInfoException(msg);
		} finally {
			releaseLock();
		}
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes() {
		return () -> getTypeStream().iterator();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		acquireLock();
		try {
			return libMap.values()
					.stream()
					.flatMap(ClassTypeInfoManager::getTypeStream);
		} finally {
			releaseLock();
		}
	}

	@Override
	public int getTypeCount() {
		acquireLock();
		try {
			return libMap.values()
					.stream()
					.mapToInt(ClassTypeInfoManager::getTypeCount)
					.sum();
		} finally {
			releaseLock();
		}
	}

	void acquireLock() {
		getDB(archive).getLock().acquire();
	}

	void releaseLock() {
		getDB(archive).getLock().release();
	}

	ClassTypeInfoManagerPlugin getPlugin() {
		return plugin;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? ICONS[0] : ICONS[1];
	}

	@Override
	public boolean canUpdate() {
		return archive.isModifiable();
	}

	@Override
	public void save() {
		plugin.getDataTypeManagerHandler().save(getDB(archive));
	}

	public Collection<LibraryClassTypeInfoManager> getLibraries() {
		return Collections.unmodifiableCollection(libMap.values());
	}

	public LibraryClassTypeInfoManager getLibrary(String name) {
		return libMap.get(name);
	}

	@Override
	public TypeInfoTreeNodeManager getTreeNodeManager() {
		return treeNodeManager;
	}

	@Override
	public ClassTypeInfoDB getType(long key) {
		throw new UnsupportedOperationException("Cannot get type from project archive by key");
	}

	public void insert(ClassTypeInfoManager manager, TaskMonitor monitor)
			throws CancelledException {
		insert(List.of(manager), monitor);
	}

	public void insert(Collection<? extends ClassTypeInfoManager> managers, TaskMonitor monitor)
			throws CancelledException {
		String format = "Inserting %s (%d/%d)";
		int size = managers.size();
		int i = 0;
		for (ClassTypeInfoManager manager : managers) {
			monitor.checkCanceled();
			monitor.setMessage(String.format(format, manager.getName(), ++i, size));
			doInsert(manager, monitor);
		}
	}

	private void doInsert(ClassTypeInfoManager manager, TaskMonitor monitor)
			throws CancelledException {
		if (manager instanceof ProjectClassTypeInfoManager) {
			TaskMonitor dummy = new CancelOnlyWrappingTaskMonitor(monitor);
			Collection<LibraryClassTypeInfoManager> managers =
				((ProjectClassTypeInfoManager) manager).libMap.values();
			insert(managers, dummy);
			return;
		}
		LibraryClassTypeInfoManager libManager = getManager(manager.getName());
		plugin.managerAdded(libManager);
		acquireLock();
		try {
			int id = startTransaction("Adding " + manager.getName());
			monitor.initialize(manager.getTypeCount());
			for (ClassTypeInfo type : manager.getTypes()) {
				monitor.checkCanceled();
				libManager.resolve(type);
				monitor.incrementProgress(1);
			}
			endTransaction(id, true);
		} finally {
			releaseLock();
		}
	}

	@Override
	public void close() {
		plugin.getDataTypeManagerHandler().closeArchive(archive);
	}

	private class LibraryMap {

		private static final String NAME = "LibraryMap";

		private final HashMap<String, LibraryClassTypeInfoManager> libMap;
		private final Table table;

		LibraryMap() {
			Table tmp = dbHandle.getTable(NAME);
			if (tmp == null) {
				try {
					long id = dbHandle.startTransaction();
					tmp = dbHandle.createTable(NAME, SCHEMA, new int[] { 0 });
					dbHandle.endTransaction(id, true);
				} catch (IOException e) {
					dbError(e);
				}
			}
			this.table = tmp;
			this.libMap = new HashMap<>(table.getRecordCount());
			fillMap();
		}

		public Collection<LibraryClassTypeInfoManager> values() {
			return libMap.values();
		}

		public boolean containsKey(String name) {
			return libMap.containsKey(name);
		}

		private void fillMap() {
			try {
				db.Record record;
				for (RecordIterator it = table.iterator(); it.hasNext();) {
					record = it.next();
					String name = record.getString(0);
					String typeTableName = record.getString(1);
					String vtableTableName = record.getString(2);
					ArchivedRttiTablePair tables =
						new ArchivedRttiTablePair(
							getClassTable(typeTableName),
							getVtableTable(vtableTableName));
					LibraryClassTypeInfoManager man =
						new LibraryClassTypeInfoManager(
							ProjectClassTypeInfoManager.this,
							tables,
							dbHandle,
							name);
					libMap.put(name, man);
				}
			} catch (IOException e) {
				dbError(e);
			}
		}

		LibraryClassTypeInfoManager get(String name) {
			return libMap.get(name);
		}

		void put(String name, LibraryClassTypeInfoManager man) {
			acquireLock();
			try {
				long id = dbHandle.startTransaction();
				libMap.put(name, man);
				ArchivedRttiTablePair tables = man.getTables();
				db.Record record = SCHEMA.createRecord(table.getKey());
				record.setString(0, name);
				record.setString(1, tables.getTypeTable().getName());
				record.setString(2, tables.getVtableTable().getName());
				table.putRecord(record);
				dbHandle.endTransaction(id, true);
			} catch (IOException e) {
				dbError(e);
			} finally {
				releaseLock();
			}
		}
	}

	public static FileArchiveClassTypeInfoManager openIfManagerArchive(
			ClassTypeInfoManagerPlugin plugin, Archive archive) throws IOException {
		if (archive instanceof ProjectArchive) {
			DBHandle handle = getDB((ProjectArchive) archive).getDBHandle();
			if (handle.getTable(LibraryMap.NAME) != null) {
				return open(plugin, (ProjectArchive) archive);
			}
		}
		return null;
	}

	public Stream<LibraryClassTypeInfoManager> getAvailableManagers(String[] names) {
		Stream.Builder<LibraryClassTypeInfoManager> builder = Stream.builder();
		for (String name : names) {
			if (libMap.containsKey(name)) {
				builder.add(libMap.get(name));
			}
		}
		return builder.build();
	}

}