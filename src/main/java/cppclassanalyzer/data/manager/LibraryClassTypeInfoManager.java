package cppclassanalyzer.data.manager;

import java.io.IOException;
import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNodeManager;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.caches.ArchivedRttiCachePair;
import cppclassanalyzer.data.manager.tables.ArchivedRttiTablePair;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.utils.TransactionHandler;
import db.DBHandle;

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

public final class LibraryClassTypeInfoManager implements ClassTypeInfoManager {

	private final ProjectClassTypeInfoManager manager;
	private final TypeInfoTreeNodeManager treeNodeManager;
	private final RttiRecordWorker worker;
	private final String name;

	LibraryClassTypeInfoManager(ProjectClassTypeInfoManager manager, ArchivedRttiTablePair tables,
			DBHandle dbHandle, String name) {
		this.manager = manager;
		this.treeNodeManager =
			new TypeInfoTreeNodeManager(this, dbHandle, name);
		this.worker = new RttiRecordWorker(tables, new ArchivedRttiCachePair());
		this.name = name;
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

	private final class RttiRecordWorker extends ArchiveRttiRecordWorker {

		RttiRecordWorker(ArchivedRttiTablePair tables, ArchivedRttiCachePair caches) {
			super(LibraryClassTypeInfoManager.this, tables, caches, getHandler());
		}

		@Override
		void acquireLock() {
			manager.acquireLock();
		}

		@Override
		void releaseLock() {
			manager.releaseLock();
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