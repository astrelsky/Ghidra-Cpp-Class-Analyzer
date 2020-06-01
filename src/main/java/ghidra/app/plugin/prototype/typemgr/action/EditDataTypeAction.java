package ghidra.app.plugin.prototype.typemgr.action;

import ghidra.app.plugin.prototype.typemgr.node.TypeInfoNode;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import docking.ActionContext;

final class EditDataTypeAction extends AbstractTypeInfoNodeAction {

	private static final String NAME = "Edit";
	private static final String DESCRIPTION = "Edit DataType";

	EditDataTypeAction(TypeInfoArchiveHandler handler) {
		super(NAME, handler);
	}

	@Override
	public final String getDescription() {
		return DESCRIPTION;
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