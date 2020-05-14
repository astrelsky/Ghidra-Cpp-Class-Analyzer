package ghidra.app.plugin.prototype.typemgr.actions;

import java.io.File;

import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;

import generic.jar.ResourceFile;
import utility.application.ApplicationLayout;

class CppClassAnalyzerPreferences {

	private static final String EXTENSION_NAME = "Ghidra-Cpp-Class-Analyzer";
	static final String LAST_OPENED_TYPE_INFO_ARCHIVE_PATH = "LastOpenedTypeInfoArchiveDirectory";

	private CppClassAnalyzerPreferences() {
	}

	private static File getRoot() {
		ApplicationLayout layout = Application.getApplicationLayout();
		ResourceFile path = layout.getExtensionInstallationDir();
		return new File(path.getFile(false), EXTENSION_NAME);
	}

	static File getLastOpenedArchivePath() {
		String path = Preferences.getProperty(LAST_OPENED_TYPE_INFO_ARCHIVE_PATH);
		if (path != null) {
			return new File(path);
		}
		return new File(getRoot(), "data");
	}

	static void setLastOpenedArchivePath(File path) {
		Preferences.setProperty(LAST_OPENED_TYPE_INFO_ARCHIVE_PATH, path.getAbsolutePath());
	}

}