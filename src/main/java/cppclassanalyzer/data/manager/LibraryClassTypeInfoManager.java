package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNodeManager;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.caches.ArchivedRttiCachePair;
import cppclassanalyzer.data.manager.tables.ArchivedRttiTablePair;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.utils.TransactionHandler;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;

import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * A ClassTypeInfoManager representing an external library
 */
public final class LibraryClassTypeInfoManager implements ClassTypeInfoManager {

	private final ProjectClassTypeInfoManager manager;
	private final TypeInfoTreeNodeManager treeNodeManager;
	private final RttiRecordWorker worker;
	private String name;

	LibraryClassTypeInfoManager(ProjectClassTypeInfoManager manager, ArchivedRttiTablePair tables,
			String name) {
		this.manager = manager;
		this.worker = new RttiRecordWorker(tables, new ArchivedRttiCachePair());
		this.name = name;
		this.treeNodeManager = new TypeInfoTreeNodeManager(manager.getPlugin(), this);
		treeNodeManager.generateTree();
	}

	ArchivedRttiTablePair getTables() {
		return worker.getTables();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public ArchivedClassTypeInfo resolve(ClassTypeInfo type) {
		return worker.resolve(type);
	}

	@Override
	public ArchivedClassTypeInfo getType(GhidraClass gc) {
		return worker.getType(gc);
	}

	@Override
	public ArchivedClassTypeInfo getType(Function fun) {
		return worker.getType(fun);
	}

	@Override
	public ArchivedClassTypeInfo getType(String name, Namespace namespace) {
		return worker.getType(name, namespace);
	}

	@Override
	public ArchivedClassTypeInfo getType(String symbolName) {
		return worker.getType(symbolName);
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes() {
		return worker.getTypes();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		return worker.getTypeStream();
	}

	@Override
	public int getTypeCount() {
		return worker.getTables().getTypeTable().getRecordCount();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (expanded) {
			return DataTypeUtils.getOpenFolderIcon(false);
		}
		return DataTypeUtils.getClosedFolderIcon(false);
	}

	@Override
	public TypeInfoTreeNodeManager getTreeNodeManager() {
		return treeNodeManager;
	}

	@Override
	public ArchivedClassTypeInfo getType(long key) {
		return worker.getType(key);
	}

	/**
	 * Gets the project manager containing this library
	 * @return the project manager
	 */
	public ProjectClassTypeInfoManager getProjectManager() {
		return manager;
	}

	@Override
	public void dbError(IOException e) {
		manager.dbError(e);
	}

	private TransactionHandler getHandler() {
		return manager.getHandler();
	}

	/**
	 * Renames this library
	 * @param name the new library name
	 * @throws InvalidNameException if the new name is invalid
	 * @throws DuplicateNameException if a library with this name already exists
	 * in the project manager.
	 */
	public void rename(String name) throws InvalidNameException, DuplicateNameException {
		manager.getLibMap().rename(this.name, name);
		this.name = name;
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public void dispose() {
		if (treeNodeManager != null) {
			treeNodeManager.dispose();
		}
	}

	DatabaseObject getArchivedData(String symbolName) {
		return worker.getArchivedData(symbolName);
	}

	private final class RttiRecordWorker extends ArchiveRttiRecordWorker {

		RttiRecordWorker(ArchivedRttiTablePair tables, ArchivedRttiCachePair caches) {
			super(LibraryClassTypeInfoManager.this, tables, caches, getHandler());
		}

		@Override
		ClassTypeInfoManagerPlugin getPlugin() {
			return manager.getPlugin();
		}

		@Override
		public DataTypeManager getDataTypeManager() {
			return manager;
		}
	}
}
