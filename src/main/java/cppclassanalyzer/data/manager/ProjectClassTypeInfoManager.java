package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNodeManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.database.data.ProjectDataTypeManager;

import cppclassanalyzer.data.ArchivedRttiData;
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
import ghidra.program.util.ChangeManager;
import ghidra.util.InvalidNameException;
import ghidra.util.Lock;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import cppclassanalyzer.database.tables.ArchivedClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.ArchivedGnuVtableDatabaseTable;
import cppclassanalyzer.database.utils.TransactionHandler;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import db.DBConstants;
import db.DBHandle;
import db.RecordIterator;
import db.Schema;
import db.StringField;
import db.Table;
import resources.ResourceManager;

/**
 * A ClassTypeInfoManager representing a project containing external libraries
 */
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

	private static final int NAME_INDEX = 0;
	private static final int TYPE_INDEX = 1;
	private static final int VTABLE_INDEX = 2;

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
			Table classTable = dbHandle.createTable(
				name + " " + ArchivedClassTypeInfo.TABLE_NAME,
				ArchivedClassTypeInfoSchema.SCHEMA,
				ArchivedClassTypeInfoSchema.INDEXED_COLUMNS);
			return new ArchivedClassTypeInfoDatabaseTable(classTable);
		} finally {
			releaseLock();
		}
	}

	private ArchivedGnuVtableDatabaseTable createVtableTable(String name) throws IOException {
		acquireLock();
		try {
			Table vtableTable = dbHandle.createTable(
				name + " " + ArchivedGnuVtable.TABLE_NAME,
				ArchivedGnuVtableSchema.SCHEMA,
				ArchivedGnuVtableSchema.INDEXED_COLUMNS);
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
	public boolean isModifiable() {
		return archive.isModifiable();
	}

	@Override
	public void save() {
		plugin.getDataTypeManagerHandler().save(getDB(archive));
	}

	/**
	 * Gets a collection of libraries contained within this project manager
	 * @return the collection of libraries
	 */
	public Collection<LibraryClassTypeInfoManager> getLibraries() {
		return Collections.unmodifiableCollection(libMap.values());
	}

	/**
	 * Gets the library in this project with the specified name
	 * @param name the name of the library
	 * @return the library manager or null if none exists
	 */
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

	/**
	 * Inserts a ClassTypeInfoManager into this project
	 * @param manager the manager to insert
	 * @param monitor the current task monitor
	 * @throws CancelledException if the operation is cancelled
	 */
	public void insert(ClassTypeInfoManager manager, TaskMonitor monitor)
			throws CancelledException {
		insert(List.of(manager), monitor);
	}

	/**
	 * Inserts the collection of managers into this project
	 * @param managers the collection of managers to insert
	 * @param monitor the current task monitor
	 * @throws CancelledException if the operation is cancelled
	 */
	public void insert(Collection<? extends ClassTypeInfoManager> managers, TaskMonitor monitor)
			throws CancelledException {
		String format = "Inserting %s (%d/%d)";
		int size = managers.size();
		int i = 0;
		for (ClassTypeInfoManager manager : managers) {
			monitor.checkCanceled();
			String msg = String.format(format, manager.getName(), ++i, size);
			//int id = startTransaction(msg);
			monitor.setMessage(msg);
			doInsert(manager, monitor);
			//endTransaction(id, true);
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
			monitor.initialize(manager.getTypeCount());
			for (ClassTypeInfo type : manager.getTypes()) {
				monitor.checkCanceled();
				libManager.resolve(type);
				monitor.incrementProgress(1);
			}
		} finally {
			releaseLock();
		}
	}

	/**
	 * Executes the provided background command in the provided tool
	 * on this manager.
	 * @param tool the plugin tool
	 * @param cmd the background command
	 */
	public void executeCommand(PluginTool tool, BackgroundCommand cmd) {
		tool.executeBackgroundCommand(cmd, archive.getDomainObject());
	}

	LibraryMap getLibMap() {
		return libMap;
	}

	@Override
	public void close() {
		archive.close();
	}

	/**
	 * Initialize the {@link ProjectArchive} as a ClassTypeInfoManager
	 * @param archive the project archive
	 * @throws IOException if an error occurs initializing the archive
	 */
	public static void init(ProjectArchive archive) throws IOException {
		Lock lock = getDB(archive).getLock();
		lock.acquire();
		try {
			Table table = createLibMapTable(getDBHandle(archive));
			getDB(archive).setChanged(ChangeManager.DOCR_OBJECT_CREATED, null, table);
		} finally {
			lock.release();
		}
	}

	private static Table createLibMapTable(DBHandle dbHandle) throws IOException {
		Table table = dbHandle.getTable(LibraryMap.NAME);
		if (table != null) {
			return table;
		}
		long id = dbHandle.startTransaction();
		boolean success = false;
		try {
			table = dbHandle.createTable(LibraryMap.NAME, SCHEMA, new int[] { NAME_INDEX });
			success = true;
			return table;
		} finally {
			dbHandle.endTransaction(id, success);
		}
	}

	public <T extends ArchivedRttiData> T getRttiData(Class<T> clazz, String symbolName) {
		return libMap.values()
			.stream()
			.map(lib -> lib.getArchivedData(symbolName))
			.filter(clazz::isInstance)
			.map(clazz::cast)
			.findFirst()
			.orElse(null);
	}

	/**
	 * Opens the Archive iff it contains a ProjectClassTypeInfoManager
	 * @param plugin the plugin
	 * @param archive the archive to open
	 * @return the manager or null if it did not contain one
	 * @throws IOException if an error occurs opening the archive
	 */
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

	/**
	 * Gets a stream of all available managers with the provided names
	 * @param names the names of the libraries to get
	 * @return a stream of all available specified libraries
	 */
	public Stream<LibraryClassTypeInfoManager> getAvailableManagers(Collection<String> names) {
		Stream.Builder<LibraryClassTypeInfoManager> builder = Stream.builder();
		for (String name : names) {
			if (libMap.containsKey(name)) {
				builder.add(libMap.get(name));
			}
		}
		return builder.build();
	}

	/**
	 * Gets a stream of all available managers with the provided names
	 * @param names the names of the libraries to get
	 * @return a stream of all available specified libraries
	 * @see #getAvailableManagers(Collection)
	 */
	public Stream<LibraryClassTypeInfoManager> getAvailableManagers(String[] names) {
		return getAvailableManagers(List.of(names));
	}

	private void endTransaction(long id, boolean commit) {
		endTransaction((int) id, commit);
	}

	TransactionHandler getHandler() {
		return new TransactionHandler(this::startTransaction, this::endTransaction);
	}

	class LibraryMap {

		private static final String NAME = "LibraryMap";
		private static final int NAME_ORDINAL = 0;

		private final HashMap<String, LibraryClassTypeInfoManager> libMap;
		private final Table table;

		LibraryMap() {
			Table tmp = dbHandle.getTable(NAME);
			if (tmp == null) {
				try {
					tmp = createLibMapTable(dbHandle);
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
				libMap.put(name, man);
				ArchivedRttiTablePair tables = man.getTables();
				db.Record record = SCHEMA.createRecord(table.getKey());
				record.setString(NAME_INDEX, name);
				record.setString(TYPE_INDEX, tables.getTypeTable().getName());
				record.setString(VTABLE_INDEX, tables.getVtableTable().getName());
				table.putRecord(record);
			} catch (IOException e) {
				dbError(e);
			} finally {
				releaseLock();
			}
		}

		db.Record getRecord(String name) {
			acquireLock();
			try {
				StringField nameField = new StringField(name);
				long[] keys = table.findRecords(nameField, NAME_ORDINAL);
				if (keys.length > 1) {
					throw new AssertException("Duplicate library "+name+" detected");
				}
				if (keys.length == 1) {
					return table.getRecord(keys[0]);
				}
			} catch (IOException e) {
				dbError(e);
			} finally {
				releaseLock();
			}
			return null;
		}

		void rename(String oldName, String newName)
				throws InvalidNameException, DuplicateNameException {
			if (newName == null || newName.length() == 0) {
				throw new InvalidNameException("Name is invalid: " + newName);
			}
			if (oldName.equals(newName)) {
				return;
			}
			if (libMap.containsKey(newName)) {
				throw new DuplicateNameException(newName + " already exists");
			}
			int id = startTransaction("Renaming "+oldName+" to "+newName);
			boolean success = false;
			acquireLock();
			try {
				db.Record record = getRecord(oldName);
				if (record == null) {
					throw new AssertException("Library "+oldName+" does not exist");
				}
				Renamer renamer = new Renamer(libMap.remove(oldName), newName, record);
				renamer.renameTypeTable();
				renamer.renameVtableTable();
				libMap.put(newName, renamer.getManager());
				table.putRecord(record);
				success = true;
			} catch (IOException e) {
				dbError(e);
			} finally {
				endTransaction(id, success);
				releaseLock();
			}
		}
	}

	private class Renamer {
		private final LibraryClassTypeInfoManager manager;
		private final String name;
		private final db.Record record;

		Renamer(LibraryClassTypeInfoManager manager, String name, db.Record record) {
			this.manager = manager;
			this.name = name;
			this.record = record;
			record.setString(NAME_INDEX, name);
		}

		void renameTypeTable() throws DuplicateNameException {
			rename(manager.getTables().getTypeTable(), TYPE_INDEX);
		}

		void renameVtableTable() throws DuplicateNameException {
			rename(manager.getTables().getVtableTable(), VTABLE_INDEX);
		}

		private void rename(Table table, int index) throws DuplicateNameException {
			acquireLock();
			try {
				String oldName = table.getName();
				table.setName(oldName.replace(manager.getName(), name));
				record.setString(index, table.getName());
			} finally {
				releaseLock();
			}
		}

		LibraryClassTypeInfoManager getManager() {
			return manager;
		}
	}
}
