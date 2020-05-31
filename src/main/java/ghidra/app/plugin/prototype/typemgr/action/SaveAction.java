package ghidra.app.plugin.prototype.typemgr.action;

import docking.ActionContext;
import docking.action.MenuData;

final class SaveAction extends AbstractFileArchivePopupAction {

	SaveAction(TypeInfoArchiveHandler handler) {
		super("Save File Type Info Archive", handler);
		setPopupMenuData(new MenuData(new String[] { "Save..." }, null, "File"));

		setDescription("Saves the selected type info archive.");
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (super.isAddToPopup(context)) {
			return getManager(context).canUpdate();
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
}