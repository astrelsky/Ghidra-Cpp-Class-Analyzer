package cppclassanalyzer.plugin.typemgr.action;

import javax.swing.Icon;

import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoArchiveNode;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNode;

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

	final DataTypeManagerHandler getDataTypeManagerHandler() {
		return handler.getPlugin().getDataTypeManagerHandler();
	}

	abstract MenuGroupType getGroup();

	Icon getIcon() {
		return null;
	}

	TypeInfoArchiveHandler getHandler() {
		return handler;
	}

	ClassTypeInfoManager getManager(ActionContext context) {
		TypeInfoArchiveNode node = handler.getArchiveNode(context);
		return node != null ? node.getTypeManager() : null;
	}

	TypeInfoTreeNode getSelectedNode(ActionContext context) {
		return handler.getTreeNode(context);
	}

	static enum MenuGroupType {
		FILE("File"),
		EDIT("Edit"),
		ARCHIVE("Archive"),
		TYPEINFO("TypeInfo");

		private final String displayName;

		MenuGroupType(String displayName) {
			this.displayName = displayName;
		}
	};
}
