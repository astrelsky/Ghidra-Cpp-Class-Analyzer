package ghidra.app.services;

import java.io.IOException;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;


@ServiceInfo(defaultProvider = DataTypeManagerPlugin.class, description = "Service to provide list of ClassTypeInfoManagers")
public interface ClassTypeInfoManagerService {

	public void addClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener);

	public void removeClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener);

	public void closeArchive(ClassTypeInfoManager manager);

	public ClassTypeInfoManager openClassTypeInfoArchive(String archiveName)
			throws IOException, DuplicateIdException;

	public ClassTypeInfoManager getManager(Program program);

}