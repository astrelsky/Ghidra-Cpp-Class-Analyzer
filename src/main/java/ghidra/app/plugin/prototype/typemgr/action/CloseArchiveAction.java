package ghidra.app.plugin.prototype.typemgr.action;

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
	public void actionPerformed(ActionContext context) {
		getHandler().getPlugin().closeArchive(getManager(context));
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.FILE;
	}

}