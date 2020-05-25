package ghidra.app.plugin.prototype.typemgr.action;

import java.io.File;
import java.io.IOException;

import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.data.manager.FileArchiveClassTypeInfoManager;
import ghidra.util.Msg;

import docking.ActionContext;
import docking.action.MenuData;

class OpenForEditAction extends AbstractFileArchivePopupAction {

	OpenForEditAction(TypeInfoArchiveHandler handler) {
		super("Open File Type Info Archive For Editing", handler);
		setPopupMenuData(new MenuData(new String[] { "Open for editing..." }, null, "File"));

		setDescription("Opens an existing type info archive for editing");
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (super.isAddToPopup(context)) {
			return !getManager(context).canUpdate();
		}
		return false;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (super.isEnabledForContext(context)) {
			return !getManager(context).canUpdate();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		FileArchiveClassTypeInfoManager manager = getManager(context);
		File file = new File(manager.getPath());
		ClassTypeInfoManagerPlugin plugin = getHandler().getPlugin();
		plugin.closeArchive(manager);
		try {
			plugin.openArchive(file, true);
		} catch (IOException e) {
			Msg.showError(plugin, null, "Failed to open archive for editing", e);
		}
	}
}