package cppclassanalyzer.plugin.typemgr.action;

import docking.ActionContext;

final class SaveAction extends AbstractFileArchivePopupAction {

	SaveAction(TypeInfoArchiveHandler handler) {
		super("Save File Archive", handler);
	}

	@Override
	public String getDescription() {
		return "Saves the selected type info archive";
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (super.isAddToPopup(context)) {
			return getManager(context).isModifiable();
		}
		return false;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (super.isEnabledForContext(context)) {
			return getManager(context).isChanged();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		getManager(context).save();
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.FILE;
	}
}
