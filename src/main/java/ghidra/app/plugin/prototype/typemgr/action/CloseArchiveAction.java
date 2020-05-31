package ghidra.app.plugin.prototype.typemgr.action;

import docking.ActionContext;
import docking.action.MenuData;

final class CloseArchiveAction extends AbstractFileArchivePopupAction {

	private static final String NAME = "Close";
	private static final String DESCRIPTION = "Closes a type info archive.";
	CloseArchiveAction(TypeInfoArchiveHandler handler) {
		super(NAME, handler);

		setPopupMenuData(new MenuData(new String[] {NAME}, null, FILE_GROUP));

		setDescription(DESCRIPTION);
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		getHandler().getPlugin().closeArchive(getManager(context));
	}

}