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
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

public class LibraryClassTypeInfoManager implements ClassTypeInfoManager {

	private final ProjectClassTypeInfoManager manager;
	private final TypeInfoTreeNodeManager treeNodeManager;
	private final RttiRecordWorker worker;
	private final String name;

	LibraryClassTypeInfoManager(ProjectClassTypeInfoManager manager, ArchivedRttiTablePair tables,
			TypeInfoTreeNodeManager treeNodeManager, String name) {
		this.manager = manager;
		this.treeNodeManager = treeNodeManager;
		this.worker = new RttiRecordWorker(tables, new ArchivedRttiCachePair());
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public ClassTypeInfoDB resolve(ClassTypeInfo type) {
		return worker.resolve(type);
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
	public ClassTypeInfoDB getType(long key) {
		return worker.getType(key);
	}

	private final class RttiRecordWorker extends ArchiveRttiRecordWorker {

		private int id = -1;

		RttiRecordWorker(ArchivedRttiTablePair tables, ArchivedRttiCachePair caches) {
			super(manager, tables, caches);
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
		public void startTransaction(String description) {
			id = manager.startTransaction(description);
		}

		@Override
		public void endTransaction() {
			if (id != -1) {
				manager.endTransaction(id, true);
				id = -1;
			}
		}

		@Override
		ClassTypeInfoManagerPlugin getPlugin() {
			return manager.getPlugin();
		}
	}

	@Override
	public void dbError(IOException e) {
		manager.dbError(e);
	}

}