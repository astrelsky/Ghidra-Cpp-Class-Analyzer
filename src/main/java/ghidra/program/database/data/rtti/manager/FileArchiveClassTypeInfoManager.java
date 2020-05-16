package ghidra.program.database.data.rtti.manager;

import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.model.data.FileBasedDataTypeManager;

interface FileArchiveClassTypeInfoManager extends ClassTypeInfoManager, FileBasedDataTypeManager {
	public final static String EXTENSION = "gcti"; // Ghidra Class Type Infos
	public static final String CONTENT_TYPE = "ClassTypeInfoArchive";
	public static final String SUFFIX = "." + EXTENSION;
}