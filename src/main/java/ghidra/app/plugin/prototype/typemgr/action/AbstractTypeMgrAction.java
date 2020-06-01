package ghidra.app.plugin.prototype.typemgr.action;

import javax.swing.Icon;

import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNode;

import cppclassanalyzer.data.ClassTypeInfoManager;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

abstract class AbstractTypeMgrAction extends DockingAction {

	private final TypeInfoArchiveHandler handler;
	private final MenuData data;

	AbstractTypeMgrAction(String name, TypeInfoArchiveHandler handler) {
		super(name, handler.getPlugin().getName());
		this.handler = handler;
		this.data = new MenuData(
			new String[] {getName()}, getIcon(), getGroup().displayName);
		setEnabled(true);
	}

	final void setPopupMenu() {
		setPopupMenuData(data);
	}

	final void setMenuBar() {
		setMenuBarData(data);
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
		EDIT("Edit"),
		ARCHIVE("Archive");

		private final String displayName;

		MenuGroupType(String displayName) {
			this.displayName = displayName;
		}
	};
}