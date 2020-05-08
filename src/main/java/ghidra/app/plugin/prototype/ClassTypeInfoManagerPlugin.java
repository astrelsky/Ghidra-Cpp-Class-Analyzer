package ghidra.app.plugin.prototype;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.rtti.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.model.data.DataTypeManagerChangeListener;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.Program;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;

/**
 * Plugin to pop up the dialog to manage rtti in the program
 * and archived rtti files. The dialog shows a single tree with
 * different classes.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "Ghidra C++ Class Analyzer",
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Window for managing rtti",
	description = "Provides the window for managing rtti " +
			"The rtti display shows all rtti found in the " +
			"current program, and rtti in all open archives.",
	servicesProvided = { ClassTypeInfoManagerService.class },
	servicesRequired = { DataTypeManagerService.class }
)
//@formatter:on
public class ClassTypeInfoManagerPlugin extends ProgramPlugin
		implements ClassTypeInfoManagerService, DomainObjectListener, PopupActionProvider {

	private static final Set<ClassTypeInfoManagerPlugin> plugins =
		Collections.synchronizedSet(new HashSet<>());
	private final List<ClassTypeInfoManager> managers;

	public ClassTypeInfoManagerPlugin(PluginTool tool) {
		super(tool, true, true);
		plugins.add(this);
		this.managers = new ArrayList<>();
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// TODO Auto-generated method stub
		System.out.println("domainObjectChanged");
	}

	@Override
	public void addClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener) {
		// TODO Auto-generated method stub
		System.out.println("addClassTypeInfoManagerChangeListener");
	}

	@Override
	public void removeClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener) {
		// TODO Auto-generated method stub
		System.out.println("removeClassTypeInfoManagerChangeListener");
	}

	@Override
	public void closeArchive(ClassTypeInfoManager manager) {
		managers.remove(manager);
		if (manager instanceof StandAloneDataTypeManager) {
			((StandAloneDataTypeManager) manager).close();
		}
	}

	@Override
	public ClassTypeInfoManager openClassTypeInfoArchive(String archiveName)
			throws IOException, DuplicateIdException {
		File file = new File(archiveName);
		if (!file.exists()) {
			throw new IOException(archiveName + " does not exist");
		}
		return ArchiveClassTypeInfoManager.open(file);
	}

	@Override
	protected void programOpened(Program program) {
		program.addListener(this);
		managers.add(new ClassTypeInfoManagerDB((ProgramDB) program));
	}

	@Override
	protected void programClosed(Program program) {
		program.removeListener(this);
		managers.remove(getManager(program));
	}

	@Override
	public ProgramClassTypeInfoManager getManager(Program program) {
		return managers.stream()
		.filter(ProgramClassTypeInfoManager.class::isInstance)
		.map(ProgramClassTypeInfoManager.class::cast)
		.filter(m -> m.getProgram().equals(program))
		.findAny()
		.orElseThrow();
	}

	public static boolean isEnabled(Program program) {
		// check program's listeners for instance of this
		DomainFile f = program.getDomainFile();
		return plugins.stream()
			.map(Plugin::getTool)
			.map(PluginTool::getDomainFiles)
			.flatMap(Arrays::stream)
			.anyMatch(f::equals);
	}

	@Override
	protected void dispose() {
		plugins.remove(this);
	}
}