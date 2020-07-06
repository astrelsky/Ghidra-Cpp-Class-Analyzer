package cppclassanalyzer.data.manager;

import cppclassanalyzer.data.ClassTypeInfoManager;
import ghidra.program.model.data.FileBasedDataTypeManager;

/**
 * A ClassTypeInfoManager implementation which is based on a FileArchive
 */
public interface FileArchiveClassTypeInfoManager extends ClassTypeInfoManager,
		FileBasedDataTypeManager {
	public final static String EXTENSION = "gcti"; // Ghidra Class Type Infos
	public static final String CONTENT_TYPE = "ClassTypeInfoArchive";
	public static final String SUFFIX = "." + EXTENSION;

	/**
	 * Saves all changed data
	 */
	public void save();

	/**
	 * Checks if the manager can be changed
	 * @return true if the manager can be changed
	 */
	public boolean isModifiable();

	/**
	 * Checks if data in the manager has been changed
	 * @return true if data has been changed
	 */
	public boolean isChanged();
}
