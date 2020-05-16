package ghidra.app.plugin.prototype.typemgr.actions;

import docking.ActionContext;
import docking.action.MenuData;

class CloseArchiveAction extends AbstractFileArchivePopupAction {

	CloseArchiveAction(TypeInfoArchiveHandler handler) {
		super("Close File Type Info Archive", handler);

		setPopupMenuData(new MenuData(new String[] { "Close File Archive..." }, null, "File"));

		setDescription("Closes a type info archive.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		getHandler().getPlugin().closeArchive(getManager(context));
	}

}