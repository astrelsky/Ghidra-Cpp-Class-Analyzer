package ghidra.app.plugin.prototype.typemgr.actions;

import javax.swing.tree.TreePath;

import ghidra.app.plugin.prototype.typemgr.TypeInfoArchiveGTree;
import ghidra.app.plugin.prototype.typemgr.TypeInfoRootNode;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;
import ghidra.program.database.data.rtti.manager.ArchiveClassTypeInfoManager;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.tree.GTreeNode;

abstract class AbstractFileArchivePopupAction extends DockingAction {

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
			if (!(node instanceof TypeInfoRootNode)) {
				return false;
			}
			if (((TypeInfoRootNode) node).isProgramNode()) {
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

	TypeInfoRootNode getNode(ActionContext context) {
		TypeInfoArchiveGTree tree = handler.getTree();
		TreePath[] selectionPaths = tree.getSelectionPaths();
		if (selectionPaths.length == 0) {
			return null;
		}
		return (TypeInfoRootNode) selectionPaths[0].getLastPathComponent();
	}

	ArchiveClassTypeInfoManager getManager(ActionContext context) {
		return (ArchiveClassTypeInfoManager) getNode(context).getManager();
	}
}