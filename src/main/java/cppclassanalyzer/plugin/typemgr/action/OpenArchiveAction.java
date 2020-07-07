package cppclassanalyzer.plugin.typemgr.action;

import java.io.File;
import java.io.IOException;

import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.util.Msg;

import docking.ActionContext;
import docking.widgets.filechooser.GhidraFileChooser;

final class OpenArchiveAction extends AbstractTypeMgrAction {

	OpenArchiveAction(TypeInfoArchiveHandler handler) {
		super("Open File Archive", handler);
		setMenuBar();
	}

	@Override
	public String getDescription() {
		return "Opens a type info archive";
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GhidraFileChooser fileChooser = new GhidraFileChooser(getHandler().getTree());

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
			getHandler().getPlugin().openArchive(file);
		} catch (IOException | DuplicateIdException e) {
			Msg.error(this, e);
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}
}
