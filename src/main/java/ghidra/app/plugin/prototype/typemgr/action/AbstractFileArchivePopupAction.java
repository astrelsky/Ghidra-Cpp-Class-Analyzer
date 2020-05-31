package ghidra.app.plugin.prototype.typemgr.action;

import javax.swing.tree.TreePath;

import ghidra.app.plugin.prototype.typemgr.TypeInfoArchiveGTree;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoArchiveNode;
import cppclassanalyzer.data.manager.FileArchiveClassTypeInfoManager;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.tree.GTreeNode;

abstract class AbstractFileArchivePopupAction extends DockingAction {

	static final String FILE_GROUP = "File";
	static final String EDIT_GROUP = "Edit";

	private final TypeInfoArchiveHandler handler;

	AbstractFileArchivePopupAction(String name, TypeInfoArchiveHandler handler) {
		super(name, handler.getPlugin().getName());
		this.handler = handler;
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

	TypeInfoArchiveHandler getHandler() {
		return handler;
	}

	TypeInfoArchiveNode getNode(ActionContext context) {
		TypeInfoArchiveGTree tree = handler.getTree();
		TreePath[] selectionPaths = tree.getSelectionPaths();
		if (selectionPaths.length == 0) {
			return null;
		}
		return (TypeInfoArchiveNode) selectionPaths[0].getLastPathComponent();
	}

	FileArchiveClassTypeInfoManager getManager(ActionContext context) {
		return (FileArchiveClassTypeInfoManager) getNode(context).getTypeManager();
	}
}