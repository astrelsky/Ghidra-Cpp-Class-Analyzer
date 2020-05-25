package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.stream.Stream;

import javax.help.UnsupportedOperationException;
import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNodeManager;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
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
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.schema.ArchivedClassTypeInfoSchema;
import cppclassanalyzer.database.schema.ArchivedGnuVtableSchema;
import cppclassanalyzer.database.tables.ArchivedClassTypeInfoDatabaseTable;
import cppclassanalyzer.database.tables.ArchivedGnuVtableDatabaseTable;
import db.DBConstants;
import db.Table;
import resources.ResourceManager;

public final class ProjectClassTypeInfoManager extends ProjectDataTypeManager
		implements FileArchiveClassTypeInfoManager {

	private static final Icon[] ICONS = new Icon[] {
		ResourceManager.loadImage("images/openBookBlue.png"),
		ResourceManager.loadImage("images/closedBookBlue.png")
	};

	private final ClassTypeInfoManagerPlugin plugin;
	private final DataTypeArchiveDB db;
	private final HashMap<String, LibraryClassTypeInfoManager> libMap;
	private final TypeInfoTreeNodeManager treeNodeManager;

	private ProjectClassTypeInfoManager(ClassTypeInfoManagerPlugin plugin, DataTypeArchiveDB db,
			int openMode) throws CancelledException, VersionException, IOException {
		super(db.getDBHandle(), openMode, db, db.getLock(), TaskMonitor.DUMMY);
		this.db = db;
		this.plugin = plugin;
		this.libMap = new HashMap<>();
		this.treeNodeManager = new TypeInfoTreeNodeManager(this, db.getDBHandle());
	}

	public static ProjectClassTypeInfoManager createManager(ClassTypeInfoManagerPlugin plugin,
			ProjectArchive archive) throws IOException {
		DataTypeArchiveDB db = (DataTypeArchiveDB) archive.getDomainObject();
		try {
			return new ProjectClassTypeInfoManager(plugin, db, DBConstants.UPDATE);
		} catch (VersionException | CancelledException e) {
			throw new AssertException(e);
		}
	}

	public static ProjectClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin,
			boolean openForUpdate) throws IOException {
		try {
			DataTypeArchiveDB db = getDb(plugin);
			int mode = openForUpdate ? DBConstants.UPDATE : DBConstants.READ_ONLY;
			return new ProjectClassTypeInfoManager(plugin, db, mode);
		} catch (IOException ioe) {
			throw ioe;
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	public static ProjectClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin)
			throws IOException {
		return open(plugin, false);
	}

	public static ProjectClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin,
			DataTypeArchiveDB archive) throws IOException {
		try {
			return new ProjectClassTypeInfoManager(plugin, archive, DBConstants.READ_ONLY);
		} catch (VersionException | CancelledException e) {
			throw new AssertException(e);
		}
	}

	private static DataTypeArchiveDB getDb(ClassTypeInfoManagerPlugin plugin) throws Exception {
		Project project = plugin.getTool().getProject();
		String name = project.getName();
		DomainFolder root = project.getProjectData().getRootFolder();
		return new DataTypeArchiveDB(root, name, plugin.getTool());
	}

	private ArchivedClassTypeInfoDatabaseTable createClassTable(String name) throws IOException {
		db.getLock().acquire();
		try {
			long id = dbHandle.startTransaction();
			Table classTable = dbHandle.createTable(
				name + " " + ArchivedClassTypeInfo.TABLE_NAME,
				ArchivedClassTypeInfoSchema.SCHEMA,
				ArchivedClassTypeInfoSchema.INDEXED_COLUMNS);
			dbHandle.endTransaction(id, true);
			return new ArchivedClassTypeInfoDatabaseTable(classTable);
		} finally {
			db.getLock().release();
		}
	}

	private ArchivedGnuVtableDatabaseTable createVtableTable(String name) throws IOException {
		db.getLock().acquire();
		try {
			long id = dbHandle.startTransaction();
			Table vtableTable = dbHandle.createTable(
				name + " " + ArchivedGnuVtable.TABLE_NAME,
				ArchivedGnuVtableSchema.SCHEMA,
				ArchivedGnuVtableSchema.INDEXED_COLUMNS);
			dbHandle.endTransaction(id, true);
			return new ArchivedGnuVtableDatabaseTable(vtableTable);
		} finally {
			db.getLock().release();
		}
	}

	@Override
	public String getName() {
		return db.getDataTypeManager().getName();
	}

	private void checkForManager(Program program) throws UnresolvedClassTypeInfoException {
		db.getLock().acquire();
		try {
			if (!libMap.containsKey(program.getName())) {
				throw new UnresolvedClassTypeInfoException(program);
			}
		} finally {
			db.getLock().release();
		}
	}

	private LibraryClassTypeInfoManager getManager(String name) {
		db.getLock().acquire();
		try {
			if (!(libMap.containsKey(name))) {
				ArchivedClassTypeInfoDatabaseTable classTable = createClassTable(name);
				ArchivedGnuVtableDatabaseTable vtableTable = createVtableTable(name);
				ArchivedRttiTablePair pair = new ArchivedRttiTablePair(classTable, vtableTable);
				TypeInfoTreeNodeManager libNodeManager =
					new TypeInfoTreeNodeManager(this, dbHandle, name);
				LibraryClassTypeInfoManager manager =
					new LibraryClassTypeInfoManager(this, pair, libNodeManager, name);
				libMap.put(name, manager);
			}
			return libMap.get(name);
		} catch (IOException e) {
			dbError(e);
		} finally {
			db.getLock().release();
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
		db.getLock().acquire();
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
			db.getLock().release();
		}
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes() {
		return () -> getTypeStream().iterator();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		db.getLock().acquire();
		try {
			return libMap.values()
					.stream()
					.flatMap(ClassTypeInfoManager::getTypeStream);
		} finally {
			db.getLock().release();
		}
	}

	@Override
	public int getTypeCount() {
		db.getLock().acquire();
		try {
			return libMap.values()
					.stream()
					.mapToInt(ClassTypeInfoManager::getTypeCount)
					.sum();
		} finally {
			db.getLock().release();
		}
	}

	void acquireLock() {
		db.getLock().acquire();
	}

	void releaseLock() {
		db.getLock().release();
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
		return db.isChangeable();
	}

	@Override
	public void save() {
		plugin.getDataTypeManagerHandler().save(db);
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

}