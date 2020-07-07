package cppclassanalyzer.plugin.typemgr.action;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import docking.ActionContext;

final class CloseArchiveAction extends AbstractFileArchivePopupAction {

	CloseArchiveAction(TypeInfoArchiveHandler handler) {
		super("Close", handler);
	}

	@Override
	public final String getDescription() {
		return "Closes a type info archive";
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (super.isAddToPopup(context)) {
			return !(getManager(context) instanceof ProgramClassTypeInfoManager);
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		getHandler().getPlugin().closeManager(getManager(context));
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.FILE;
	}

}
