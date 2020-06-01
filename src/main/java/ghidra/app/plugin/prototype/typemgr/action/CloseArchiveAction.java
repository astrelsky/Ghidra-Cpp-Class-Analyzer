package ghidra.app.plugin.prototype.typemgr.action;

import docking.ActionContext;

final class CloseArchiveAction extends AbstractFileArchivePopupAction {

	private static final String NAME = "Close";
	private static final String DESCRIPTION = "Closes a type info archive.";
	CloseArchiveAction(TypeInfoArchiveHandler handler) {
		super(NAME, handler);
	}

	@Override
	public final String getDescription() {
		return DESCRIPTION;
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