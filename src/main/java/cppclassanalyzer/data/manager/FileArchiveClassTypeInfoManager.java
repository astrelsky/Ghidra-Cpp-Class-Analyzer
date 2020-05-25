package cppclassanalyzer.data.manager;

import cppclassanalyzer.data.ClassTypeInfoManager;
import ghidra.program.model.data.FileBasedDataTypeManager;

public interface FileArchiveClassTypeInfoManager extends ClassTypeInfoManager,
		FileBasedDataTypeManager {
	public final static String EXTENSION = "gcti"; // Ghidra Class Type Infos
	public static final String CONTENT_TYPE = "ClassTypeInfoArchive";
	public static final String SUFFIX = "." + EXTENSION;

	public void save();
	public boolean canUpdate();
	public boolean isChanged();
}