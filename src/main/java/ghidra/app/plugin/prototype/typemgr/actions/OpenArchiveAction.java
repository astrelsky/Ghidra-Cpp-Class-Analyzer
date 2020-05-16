package ghidra.app.plugin.prototype.typemgr.actions;

import java.io.File;
import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;

class OpenArchiveAction extends DockingAction {

	private final TypeInfoArchiveHandler handler;

	OpenArchiveAction(TypeInfoArchiveHandler handler) {
		super("Open File Type Info Archive", handler.getPlugin().getName());
		this.handler = handler;

		setMenuBarData(new MenuData(new String[] { "Open File Archive..." }, "Archive"));

		setDescription("Opens a type info archive.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GhidraFileChooser fileChooser = new GhidraFileChooser(handler.getTree());

		File archiveDirectory = CppClassAnalyzerPreferences.getLastOpenedArchivePath();
		fileChooser.setFileFilter(CppClassAnalyzerPreferences.EXTENSION_FILTER);
		fileChooser.setCurrentDirectory(archiveDirectory);
		fileChooser.setApproveButtonText("Open Type Info Archive File");
		fileChooser.setApproveButtonToolTipText("Open Type Info Archive File");

		File file = fileChooser.getSelectedFile();
		if (file == null || !file.exists()) {
			return;
		}

		File lastOpenedDir = file.getParentFile();
		CppClassAnalyzerPreferences.setLastOpenedArchivePath(lastOpenedDir);

		try {
			handler.getPlugin().openArchive(file);
		} catch (IOException e) {
			Msg.showError(handler, null, "Failed to open Type Info Archive", e);
		}
	}
}
