package cppclassanalyzer.plugin.typemgr.action;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoNode;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import docking.ActionContext;

final class EditDataTypeAction extends AbstractTypeInfoNodeAction {

	EditDataTypeAction(TypeInfoArchiveHandler handler) {
		super("Edit", handler);
	}

	@Override
	public final String getDescription() {
		return "Edit DataType";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		TypeInfoNode node = getSelectedNode(context);
		if (node != null) {
			ClassTypeInfoDB type = node.getType();
			return type.isModifiable() && type.getClassDataTypeId() != ClassTypeInfoDB.INVALID_KEY;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ClassTypeInfoDB type = getSelectedNode(context).getType();
		getHandler().getPlugin().getDataTypeManagerPlugin().edit(type.getClassDataType());
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.EDIT;
	}
}
