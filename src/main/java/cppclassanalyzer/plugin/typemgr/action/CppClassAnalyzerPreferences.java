package cppclassanalyzer.plugin.typemgr.action;

import java.io.File;
import java.util.List;

import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.ExtensionFileFilter;

import generic.jar.ResourceFile;
import utility.application.ApplicationLayout;

final class CppClassAnalyzerPreferences {

	private static final String EXTENSION_NAME = "Ghidra-Cpp-Class-Analyzer";
	static final String ARCHIVE_EXTENSION = "cdb";
	static final ExtensionFileFilter EXTENSION_FILTER =
		new ExtensionFileFilter(
			new String[]{ CppClassAnalyzerPreferences.ARCHIVE_EXTENSION },
			"Ghidra Type Info Archive Files");
	static final String LAST_OPENED_TYPE_INFO_ARCHIVE_PATH = "LastOpenedTypeInfoArchiveDirectory";
	static final String LAST_USER_TYPE_INFO_ARCHIVE_PATH = "LastUserTypeInfoArchiveDirectory";
	static final File DEFAULT_ARCHIVE_PATH =  new File(getExtensionRoot(), "data");

	private CppClassAnalyzerPreferences() {
	}

	static File getExtensionRoot() {
		ApplicationLayout layout = Application.getApplicationLayout();
		List<ResourceFile> paths = layout.getExtensionInstallationDirs();
		for (ResourceFile path : paths) {
			File f = new File(path.getFile(false), EXTENSION_NAME);
			if (f.exists()) {
				return f;
			}
		}
		return null;
	}

	static File getLastOpenedArchivePath() {
		String path = Preferences.getProperty(LAST_OPENED_TYPE_INFO_ARCHIVE_PATH);
		if (path != null) {
			return new File(path);
		}
		return DEFAULT_ARCHIVE_PATH;
	}

	static void setLastOpenedArchivePath(File path) {
		Preferences.setProperty(LAST_OPENED_TYPE_INFO_ARCHIVE_PATH, path.getAbsolutePath());
		Preferences.store();
	}

}
