package ghidra.program.database.data.rtti.manager;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Lock;

import db.DBConstants;
import db.DBHandle;
import db.Table;
import generic.jar.ResourceFile;

public final class ProjectClassTypeInfoManager extends StandAloneDataTypeManager
		implements FileArchiveClassTypeInfoManager {

	private final ClassTypeInfoManagerPlugin plugin;
	private final Lock lock;
	private final File file;
	private final HashMap<String, SubProjectClassTypeInfoManager> libMap;

	public ProjectClassTypeInfoManager(ClassTypeInfoManagerPlugin plugin,
			File file, int openMode) throws IOException {
		super(new ResourceFile(file), openMode);
		this.lock = new Lock(getClass().getSimpleName());
		this.file = file;
		this.plugin = plugin;
		this.libMap = new HashMap<>();
	}

	public static ProjectClassTypeInfoManager createManager(ClassTypeInfoManagerPlugin plugin,
			File file) throws IOException {
		return new ProjectClassTypeInfoManager(plugin, file, DBConstants.CREATE);
	}

	public static ProjectClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin,
			File file, boolean openForUpdate) throws IOException {
		int mode = openForUpdate ? DBConstants.UPDATE : DBConstants.READ_ONLY;
		return new ProjectClassTypeInfoManager(plugin, file, mode);
	}

	public static ProjectClassTypeInfoManager open(ClassTypeInfoManagerPlugin plugin, File file)
			throws IOException {
		return open(plugin, file, false);
	}

	private Table createClassTable(String name) throws IOException {
		lock.acquire();
		try {
			long id = dbHandle.startTransaction();
			Table classTable = dbHandle.createTable(
				name + " " + ArchivedClassTypeInfo.TABLE_NAME,
				ArchivedClassTypeInfo.SCHEMA,
				ArchivedClassTypeInfo.INDEXED_COLUMNS);
			dbHandle.endTransaction(id, true);
			return classTable;
		} finally {
			lock.release();
		}
	}

	private Table createVtableTable(String name) throws IOException {
		lock.acquire();
		try {
			long id = dbHandle.startTransaction();
			Table vtableTable = dbHandle.createTable(
				name + " " + ArchivedGnuVtable.TABLE_NAME,
				ArchivedGnuVtable.SCHEMA,
				ArchivedGnuVtable.INDEXED_COLUMNS);
			dbHandle.endTransaction(id, true);
			return vtableTable;
		} finally {
			lock.release();
		}
	}

	DBHandle getHandle() {
		return dbHandle;
	}

	@Override
	public String getPath() {
		return file.getAbsolutePath();
	}


	@Override
	public String getName() {
		return plugin.getTool().getProject().getName();
	}

	private void checkForManager(Program program) throws UnresolvedClassTypeInfoException {
		lock.acquire();
		try {
			if (!libMap.containsKey(program.getName())) {
				throw new UnresolvedClassTypeInfoException(program);
			}
		} finally {
			lock.release();
		}
	}

	private SubProjectClassTypeInfoManager getManager(String name) {
		lock.acquire();
		try {
			if (!(libMap.containsKey(name))) {
				Table classTable = createClassTable(name);
				Table vtableTable = createVtableTable(name);
				RttiTablePair pair = new RttiTablePair(classTable, vtableTable);
				SubProjectClassTypeInfoManager manager =
					new SubProjectClassTypeInfoManager(this, pair, name);
				libMap.put(name, manager);
			}
			return libMap.get(name);
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
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
		lock.acquire();
		try {
			for (SubProjectClassTypeInfoManager manager : libMap.values()) {
				ClassTypeInfoDB type = manager.getType(symbolName);
				if (type != null) {
					return type;
				}
			}
			String msg = "Unable to locate an archived ClassTypeInfo with symbol name "
				+ symbolName;
			throw new UnresolvedClassTypeInfoException(msg);
		} finally {
			lock.release();
		}
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes() {
		return () -> getTypeStream().iterator();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		lock.acquire();
		try {
			return libMap.values()
				.stream()
				.flatMap(ClassTypeInfoManager::getTypeStream);
		} finally {
			lock.release();
		}
	}

	@Override
	public int getTypeCount() {
		lock.acquire();
		try {
			return libMap.values()
				.stream()
				.mapToInt(ClassTypeInfoManager::getTypeCount)
				.sum();
		} finally {
			lock.release();
		}
	}

	void acquireLock() {
		lock.acquire();
	}

	void releaseLock() {
		lock.release();
	}

	ClassTypeInfoManagerPlugin getPlugin() {
		return plugin;
	}

}