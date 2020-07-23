package cppclassanalyzer.plugin.typemgr.action;

import ghidra.app.cmd.data.rtti.Vtable;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoNode;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNode;
import docking.ActionContext;

final class GoToVtableAction extends AbstractTypeInfoNodeAction {

	GoToVtableAction(TypeInfoArchiveHandler handler) {
		super("Goto Vtable", handler);
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.TYPEINFO;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		TypeInfoTreeNode node = getSelectedNode(context);
		if (node instanceof TypeInfoNode) {
			ClassTypeInfoDB type = ((TypeInfoNode) node).getType();
			return type.getManager() instanceof ProgramClassTypeInfoManager
				&& Vtable.isValid(type.getVtable());
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		TypeInfoNode node = (TypeInfoNode) getSelectedNode(context);
		Vtable vtable = node.getType().getVtable();
		getHandler().getPlugin().goTo(vtable.getAddress());
	}

}
