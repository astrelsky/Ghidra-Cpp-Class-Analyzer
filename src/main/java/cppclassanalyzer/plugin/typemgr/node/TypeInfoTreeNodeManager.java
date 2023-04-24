package cppclassanalyzer.plugin.typemgr.node;

import ghidra.app.util.SymbolPath;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.util.Disposable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.ArchiveClassTypeInfoManager;
import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.plugin.typemgr.TypeInfoArchiveGTree;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.tasks.GTreeBulkTask;

public class TypeInfoTreeNodeManager implements DomainObjectListener, Disposable {

	private final AbstractManagerNode root;

	private TypeInfoTreeNodeManager(AbstractManagerNode root) {
		this.root = root;
		root.getTypeManager().addListener(this);
	}

	public TypeInfoTreeNodeManager(ClassTypeInfoManagerPlugin plugin,
			ProgramClassTypeInfoManager manager) {
		this(new TypeInfoRootNode(manager));
		plugin.getTree().getModelRoot().addNode(root);
	}

	public TypeInfoTreeNodeManager(ClassTypeInfoManagerPlugin plugin,
			ArchiveClassTypeInfoManager manager) {
		this(new TypeInfoRootNode(manager));
		plugin.getTree().getModelRoot().addNode(root);
	}

	@SuppressWarnings("resource")
	public TypeInfoTreeNodeManager(ClassTypeInfoManagerPlugin plugin,
			LibraryClassTypeInfoManager manager) {
		this(new TypeInfoLibraryNode(manager));
		manager.getProjectManager().getTreeNodeManager().root.addNode(root);
	}

	public TypeInfoTreeNodeManager(ClassTypeInfoManagerPlugin plugin,
			ProjectClassTypeInfoManager manager) {
		this(new ProjectArchiveTypeInfoNode(manager));
		plugin.getTree().getModelRoot().addNode(root);
	}

	private GTreeNode getParentNode(SymbolPath paths) {
		if (paths.getParent() == null) {
			return root;
		}
		GTreeNode node = root;
		for (String path : paths.getParent().asList()) {
			GTreeNode child = node.getChild(path);
			if (child == null) {
				child = new NamespacePathNode(path, this);
				node.addNode(child);
			}
			node = child;
		}
		return node;
	}

	GTreeNode createTypeNode(ClassTypeInfoDB type) {
		SymbolPath path = type.getSymbolPath();
		GTreeNode parent = getParentNode(path);
		GTreeNode existing = parent.getChild(path.getName());
		if (existing instanceof NamespacePathNode) {
			return new TypeInfoNode(type, (NamespacePathNode) existing);
		}
		if (existing instanceof TypeInfoNode) {
			return existing;
		}
		GTreeNode node = new TypeInfoNode(type);
		parent.addNode(node);
		return node;
	}

	private TypeInfoArchiveGTree getTree() {
		return (TypeInfoArchiveGTree) root.getTree();
	}

	public GTreeNode getRoot() {
		return root;
	}

	public void generateTree() {
		ManagerLoaderBulkTask task = new ManagerLoaderBulkTask(getTree(), root);
		getTree().runBulkTask(task);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (getTree() == null || !getTree().isVisible()) {
			return;
		}

		if (event.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			DomainObject source = (DomainObject) event.getSource();
			if (root.getName().equals(source.getName())) {
				root.removeAll();
				generateTree();
			}
		}
	}

	@Override
	public void dispose() {
		getTree().getModelRoot().removeNode(root);
		root.dispose();
	}

	private static class ManagerLoaderBulkTask extends GTreeBulkTask {

		private final TypeInfoArchiveNode node;

		ManagerLoaderBulkTask(GTree tree, TypeInfoArchiveNode node) {
			super(tree);
			this.node = node;
		}

		@Override
		public void runBulk(TaskMonitor monitor) throws CancelledException {
			ClassTypeInfoManager manager = node.getTypeManager();
			monitor.initialize(manager.getTypeCount());
			for (ClassTypeInfoDB type : manager.getTypes()) {
				monitor.checkCancelled();
				node.addNode(type);
				monitor.incrementProgress(1);
			}
		}
	}
}
