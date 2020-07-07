package cppclassanalyzer.plugin.typemgr.action;

import java.io.File;
import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;

final class CreateArchiveAction extends AbstractTypeMgrAction {

	CreateArchiveAction(TypeInfoArchiveHandler handler) {
		super("Create File Archive", handler);
		setMenuBar();
	}

	@Override
	public String getDescription() {
		return "Creates a new type info archive";
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ArchiveFileChooser fileChooser = getHandler().getFileChooser();
		fileChooser.setApproveButtonText("Create Archive");
		fileChooser.setApproveButtonToolTipText("Create Archive");
		fileChooser.setTitle("Create Archive");

		File file = fileChooser.promptUserForFile();
		if (file == null) {
			return;
		}

		if (file.exists()) {
			if (!fileChooser.promptForOverwrite()) {
				return;
			}
			file.delete();
		}
		try {
			getHandler().getPlugin().createArchive(file);
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}
}
