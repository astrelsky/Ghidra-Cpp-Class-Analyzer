package cppclassanalyzer.plugin.typemgr.action;

import java.io.File;
import java.io.IOException;

import cppclassanalyzer.data.manager.FileArchiveClassTypeInfoManager;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;

import ghidra.util.Msg;

import docking.ActionContext;

final class OpenForEditAction extends AbstractFileArchivePopupAction {

	OpenForEditAction(TypeInfoArchiveHandler handler) {
		super("Open for editing", handler);
	}

	@Override
	public String getDescription() {
		return "Opens an existing type info archive for editing";
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (super.isAddToPopup(context)) {
			return !getManager(context).isModifiable();
		}
		return false;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (super.isEnabledForContext(context)) {
			return !getManager(context).isModifiable();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		FileArchiveClassTypeInfoManager manager = getManager(context);
		File file = new File(manager.getPath());
		ClassTypeInfoManagerPlugin plugin = getHandler().getPlugin();
		plugin.closeManager(manager);
		try {
			plugin.openArchive(file, true);
		} catch (IOException e) {
			Msg.showError(plugin, null, "Failed to open archive for editing", e);
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.FILE;
	}
}
