package ghidra.app.services;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import ghidra.app.plugin.prototype.TypeInfoManagerListener;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.framework.plugintool.util.PluginDescription;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import docking.widgets.tree.GTree;

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

	public void closeManager(ClassTypeInfoManager manager);

	public default void openArchive(File archive)
			throws IOException, DuplicateIdException {
		openArchive(archive, false);
	}

	public void openArchive(File archive, boolean updateable)
		throws IOException, DuplicateIdException;

	public void createArchive(File archive)
		throws IOException, DuplicateIdException;

	public ProgramClassTypeInfoManager getManager(Program program);

	public List<ClassTypeInfoManager> getManagers();

	public void managerAdded(ClassTypeInfoManager manager);

	public GTree getTree();

	public static boolean isEnabled(Program program) {
		Project project = AppInfo.getActiveProject();
		PluginTool[] tools = project.getToolManager().getRunningTools();
		return Arrays.stream(tools)
			.filter(program::isUsedBy)
			.map(PluginTool::getManagedPlugins)
			.flatMap(List::stream)
			.map(Plugin::getPluginDescription)
			.map(PluginDescription::getServicesProvided)
			.anyMatch(s -> s.contains(ClassTypeInfoManagerService.class));
	}

	public ClassTypeInfo getExternalClassTypeInfo(Program program, String mangled);

}