package cppclassanalyzer.data.manager;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;

import ghidra.program.model.data.FileBasedDataTypeManager;

/**
 * A ClassTypeInfoManager implementation which is based on a FileArchive
 */
public interface FileArchiveClassTypeInfoManager extends ClassTypeInfoManager,
		FileBasedDataTypeManager {

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

	public ClassTypeInfoManagerPlugin getPlugin();
}
