package ghidra.app.plugin.prototype.typemgr.actions;

import java.io.File;
import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

class CreateArchiveAction extends DockingAction {

	private final TypeInfoArchiveHandler handler;

	CreateArchiveAction(TypeInfoArchiveHandler handler) {
		super("Create File Type Info Archive", handler.getPlugin().getName());
		this.handler = handler;

		setMenuBarData(new MenuData(new String[] { "Create File Archive..." }, "Archive"));

		setDescription("Creates a new type info archive.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ArchiveFileChooser fileChooser = handler.getFileChooser();
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
			handler.getPlugin().createArchive(file);
		} catch (IOException e) {
			Msg.showError(handler, null, "Failed to create Type Info Archive", e);
		}
	}
}
