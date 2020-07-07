package cppclassanalyzer.plugin.typemgr.action;

import javax.swing.tree.TreePath;

import cppclassanalyzer.plugin.typemgr.TypeInfoArchiveGTree;
import cppclassanalyzer.plugin.typemgr.TypeInfoTreeProvider;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoArchiveNode;
import ghidra.util.exception.AssertException;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.FileArchiveClassTypeInfoManager;
import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;
import docking.ActionContext;
import docking.widgets.tree.GTreeNode;

abstract class AbstractFileArchivePopupAction extends AbstractTypeMgrAction {

	AbstractFileArchivePopupAction(String name, TypeInfoArchiveHandler handler) {
		super(name, handler);
		setPopupMenu();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		Object provider = context.getComponentProvider();
		if (!(provider instanceof TypeInfoTreeProvider)) {
			return false;
		}
		TypeInfoArchiveGTree tree = ((TypeInfoTreeProvider) provider).getTree();
		TreePath[] selectionPaths = tree.getSelectionPaths();

		if (selectionPaths.length == 0) {
			return false;
		}

		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof TypeInfoArchiveNode)) {
				return false;
			}
			if (((TypeInfoArchiveNode) node).isProgramNode()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return isAddToPopup(context);
	}

	@Override
	final FileArchiveClassTypeInfoManager getManager(ActionContext context) {
		ClassTypeInfoManager manager = super.getManager(context);
		if (manager == null) {
			return null;
		}
		if (manager instanceof FileArchiveClassTypeInfoManager) {
			return (FileArchiveClassTypeInfoManager) manager;
		}
		if (manager instanceof LibraryClassTypeInfoManager) {
			return ((LibraryClassTypeInfoManager) manager).getProjectManager();
		}
		throw new AssertException(
			"Unexpected ClassTypeInfoManager "+manager.getClass().getSimpleName());
	}

	@Override
	final TypeInfoArchiveNode getSelectedNode(ActionContext context) {
		return getHandler().getArchiveNode(context);
	}

}
