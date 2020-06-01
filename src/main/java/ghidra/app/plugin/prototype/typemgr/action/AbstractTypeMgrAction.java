package ghidra.app.plugin.prototype.typemgr.action;

import javax.swing.Icon;

import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNode;

import cppclassanalyzer.data.ClassTypeInfoManager;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

abstract class AbstractTypeMgrAction extends DockingAction {

	private final TypeInfoArchiveHandler handler;

	AbstractTypeMgrAction(String name, TypeInfoArchiveHandler handler) {
		super(name, handler.getPlugin().getName());
		this.handler = handler;
		MenuData data = new MenuData(
			new String[] {getName()}, getIcon(), getGroup().displayName);
		setPopupMenuData(data);
		setEnabled(true);
	}

	abstract MenuGroupType getGroup();

	Icon getIcon() {
		return null;
	}

	TypeInfoArchiveHandler getHandler() {
		return handler;
	}

	ClassTypeInfoManager getManager(ActionContext context) {
		return handler.getArchiveNode(context).getTypeManager();
	}

	TypeInfoTreeNode getSelectedNode(ActionContext context) {
		return handler.getTreeNode(context);
	}

	static enum MenuGroupType {
		FILE("File"),
		EDIT("Edit");

		private final String displayName;

		MenuGroupType(String displayName) {
			this.displayName = displayName;
		}
	};
}