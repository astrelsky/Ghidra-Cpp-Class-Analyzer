package ghidra.app.services;

import java.io.IOException;

import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

//@formatter:off
@ServiceInfo(
	defaultProvider = ClassTypeInfoManagerPlugin.class,
	description = "Service to provide ClassTypeInfoManagers"
)
//@formatter:on
public interface ClassTypeInfoManagerService {

	public void addClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener);

	public void removeClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener);

	public void closeArchive(ClassTypeInfoManager manager);

	public ClassTypeInfoManager openClassTypeInfoArchive(String archiveName)
			throws IOException, DuplicateIdException;

	public ProgramClassTypeInfoManager getManager(Program program);

	public static boolean isEnabled(Program program) {
		return ClassTypeInfoManagerPlugin.isEnabled(program);
	}

}