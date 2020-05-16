package ghidra.app.services;

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.plugin.prototype.TypeInfoManagerListener;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.model.listing.Program;

//@formatter:off
@ServiceInfo(
	defaultProvider = ClassTypeInfoManagerPlugin.class,
	description = "Service to provide ClassTypeInfoManagers"
)
//@formatter:on
public interface ClassTypeInfoManagerService {

// man = state.tool.getService(ghidra.app.services.ClassTypeInfoManagerService).getManager(currentProgram)

	public void addTypeInfoManagerChangeListener(TypeInfoManagerListener listener);

	public void removeTypeInfoManagerChangeListener(TypeInfoManagerListener listener);

	public void closeArchive(ClassTypeInfoManager manager);

	public default ClassTypeInfoManager openArchive(File archive)  throws IOException {
		return openArchive(archive, false);
	}

	public ClassTypeInfoManager openArchive(File archive, boolean updateable) throws IOException;

	public ClassTypeInfoManager createArchive(File archive) throws IOException;

	public ProgramClassTypeInfoManager getManager(Program program);

	public List<ClassTypeInfoManager> getManagers();

	public static boolean isEnabled(Program program) {
		return ClassTypeInfoManagerPlugin.isEnabled(program);
	}

}