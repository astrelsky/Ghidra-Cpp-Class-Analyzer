package cppclassanalyzer.plugin.typemgr.action;

import java.util.Arrays;
import java.util.stream.Stream;

import javax.swing.tree.TreePath;

import cppclassanalyzer.plugin.typemgr.TypeInfoArchiveGTree;
import cppclassanalyzer.plugin.typemgr.TypeInfoTreeProvider;
import cppclassanalyzer.plugin.typemgr.node.NamespacePathNode;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoArchiveNode;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoNode;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNode;

import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import docking.ActionContext;
import docking.action.DockingAction;

public final class TypeInfoArchiveHandler {

	private final ClassTypeInfoManagerPlugin plugin;

	public TypeInfoArchiveHandler(ClassTypeInfoManagerPlugin plugin) {
		this.plugin = plugin;
	}

	TypeInfoTreeProvider getProvider() {
		return plugin.getProvider();
	}

	ClassTypeInfoManagerPlugin getPlugin() {
		return plugin;
	}

	ArchiveFileChooser getFileChooser() {
		return new ArchiveFileChooser(this);
	}

	TypeInfoArchiveGTree getTree() {
		return plugin.getProvider().getTree();
	}

	public DockingAction getCreateAction() {
		return new CreateArchiveAction(this);
	}

	public DockingAction getOpenAction() {
		return new OpenArchiveAction(this);
	}

	public DockingAction getCloseAction() {
		return new CloseArchiveAction(this);
	}

	public DockingAction getOpenForEditAction() {
		return new OpenForEditAction(this);
	}

	public DockingAction getSaveAction() {
		return new SaveAction(this);
	}

	public DockingAction getCreateProjectArchiveAction() {
		return new CreateProjectArchiveAction(this);
	}

	public DockingAction getOpenProjectArchiveAction() {
		return new OpenProjectArchiveAction(this);
	}

	public DockingAction getCopyArchiveAction() {
		return new CopyArchiveAction(this);
	}

	public DockingAction getPasteArchiveAction() {
		return new PasteArchiveAction(this);
	}

	public DockingAction getEditDataTypeAction() {
		return new EditDataTypeAction(this);
	}

	public DockingAction getRenameAction() {
		return new RenameManagerAction(this);
	}

	public DockingAction getGoToVtableAction() {
		return new GoToVtableAction(this);
	}

	private Stream<TypeInfoTreeNode> getSelectedNodes(ActionContext context) {
		TreePath[] selectionPaths = getTree().getSelectionPaths();
		if (selectionPaths.length == 0) {
			return Stream.empty();
		}
		return Arrays.stream(selectionPaths)
			.map(TreePath::getLastPathComponent)
			.filter(TypeInfoTreeNode.class::isInstance)
			.map(TypeInfoTreeNode.class::cast);
	}

	private <T extends TypeInfoTreeNode> T getSpecialNode(ActionContext context, Class<T> clazz) {
		return getSelectedNodes(context)
			.filter(clazz::isInstance)
			.map(clazz::cast)
			.findFirst()
			.orElse(null);
	}

	TypeInfoTreeNode getTreeNode(ActionContext context) {
		return getSelectedNodes(context)
			.findFirst()
			.orElse(null);
	}

	TypeInfoArchiveNode getArchiveNode(ActionContext context) {
		return getSpecialNode(context, TypeInfoArchiveNode.class);
	}

	TypeInfoNode getTypeInfoNode(ActionContext context) {
		return getSpecialNode(context, TypeInfoNode.class);
	}

	NamespacePathNode getNamespacePathNode(ActionContext context) {
		return getSpecialNode(context, NamespacePathNode.class);
	}
}
