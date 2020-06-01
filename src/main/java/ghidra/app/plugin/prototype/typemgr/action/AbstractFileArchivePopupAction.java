package ghidra.app.plugin.prototype.typemgr.action;

import javax.swing.tree.TreePath;

import ghidra.app.plugin.prototype.typemgr.TypeInfoArchiveGTree;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoArchiveNode;
import cppclassanalyzer.data.manager.FileArchiveClassTypeInfoManager;

import docking.ActionContext;
import docking.widgets.tree.GTreeNode;

abstract class AbstractFileArchivePopupAction extends AbstractTypeMgrAction {

	AbstractFileArchivePopupAction(String name, TypeInfoArchiveHandler handler) {
		super(name, handler);
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
		return (FileArchiveClassTypeInfoManager) super.getManager(context);
	}

	@Override
	final TypeInfoArchiveNode getSelectedNode(ActionContext context) {
		return getHandler().getArchiveNode(context);
	}

}