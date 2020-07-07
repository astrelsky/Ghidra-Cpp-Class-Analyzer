package cppclassanalyzer.plugin.typemgr.action;

import java.awt.Component;
import java.io.File;

import ghidra.framework.GenericRunInfo;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;

final class ArchiveFileChooser extends GhidraFileChooser {

	private final Component component;

	ArchiveFileChooser(TypeInfoArchiveHandler handler) {
		super(handler.getProvider().getComponent());
		this.component = handler.getProvider().getComponent();

		setFileFilter(CppClassAnalyzerPreferences.EXTENSION_FILTER);
		setApproveButtonText("Save As");
		setApproveButtonToolTipText("Save As");
	}

	public File promptUserForFile() {
		File path = CppClassAnalyzerPreferences.getLastOpenedArchivePath();
		if (path.equals(CppClassAnalyzerPreferences.DEFAULT_ARCHIVE_PATH)) {
			// DEFAULT_ARCHIVE_PATH is read only
			path = new File(GenericRunInfo.getProjectsDirPath());
		}
		setCurrentDirectory(path);
		File file = getSelectedFile();
		if (file == null) {
			return null;
		}
		if (!file.getName().endsWith(CppClassAnalyzerPreferences.ARCHIVE_EXTENSION)) {
			file = new File(
				file.getAbsolutePath() + "." + CppClassAnalyzerPreferences.ARCHIVE_EXTENSION);
		}
		CppClassAnalyzerPreferences.setLastOpenedArchivePath(file);

		return file;
	}

	/**
	 * Prompts user to overwrite existing file
	 *
	 * @return true if overwrite is accepted
	 */
	public boolean promptForOverwrite() {
		String msg = "Do you want to overwrite existing file\n"
			+ getSelectedFile().getAbsolutePath();
		return OptionDialog.showYesNoDialogWithNoAsDefaultButton(component,
			"Overwrite Existing File?", msg) == OptionDialog.OPTION_ONE;
	}
}
