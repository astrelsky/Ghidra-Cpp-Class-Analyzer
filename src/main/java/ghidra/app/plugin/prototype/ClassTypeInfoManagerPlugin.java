package ghidra.app.plugin.prototype;

import java.awt.datatransfer.Clipboard;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ArchiveManagerListener;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoNode;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import cppclassanalyzer.data.manager.ArchiveClassTypeInfoManager;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.manager.FileArchiveClassTypeInfoManager;
import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import docking.widgets.tree.GTree;

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
		implements ClassTypeInfoManagerService, PopupActionProvider, ArchiveManagerListener {

	private final List<ClassTypeInfoManager> managers;
	private final List<TypeInfoManagerListener> listeners;
	private final TypeInfoTreeProvider provider;
	private final Clipboard clipboard;
	private DataTypeManagerPlugin dtmPlugin;

	public ClassTypeInfoManagerPlugin(PluginTool tool) {
		super(tool, true, true);
		this.clipboard = new Clipboard(getName());
		this.listeners = new ArrayList<>();
		this.managers = new ArrayList<>();
		this.provider = new TypeInfoTreeProvider(tool, this);
	}

	@Override
	protected void init() {
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		dtmPlugin = (DataTypeManagerPlugin) service;
		dtmPlugin.getDataTypeManagerHandler().addArchiveManagerListener(this);
	}

	@Override
	public List<ClassTypeInfoManager> getManagers() {
		return Collections.unmodifiableList(managers);
	}

	public List<ClassTypeInfoManager> getManagersByName(List<String> names) {
		return managers.stream()
				.filter(m -> names.contains(m.getName()))
				.collect(Collectors.toList());
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		return Collections.emptyList();
	}

	@Override
	public void addTypeInfoManagerChangeListener(TypeInfoManagerListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeTypeInfoManagerChangeListener(TypeInfoManagerListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void closeManager(ClassTypeInfoManager manager) {
		if (manager instanceof FileArchiveClassTypeInfoManager) {
			((FileArchiveClassTypeInfoManager) manager).close();
		}
	}

	@Override
	public void openArchive(File file, boolean updateable) throws IOException {
		ClassTypeInfoManager manager =
			ArchiveClassTypeInfoManager.open(this, file, updateable);
		managerAdded(manager);
	}

	@Override
	public void createArchive(File file) throws IOException {
		ClassTypeInfoManager manager = ArchiveClassTypeInfoManager.createManager(this, file);
		managerAdded(manager);
	}

	public boolean hasManager(ProjectArchive archive) {
		String name = archive.getName();
		return managers.stream()
			.filter(ProjectClassTypeInfoManager.class::isInstance)
			.map(ClassTypeInfoManager::getName)
			.anyMatch(name::equals);
	}

	public void openProjectArchive(ProjectArchive archive) throws IOException {
		ClassTypeInfoManager manager = ProjectClassTypeInfoManager.open(this, archive);
		projectManagerOpened(manager);
	}

	private void projectManagerOpened(ClassTypeInfoManager manager) {
		managerAdded(manager);
	}

	@Override
	protected void programOpened(Program program) {
		managers.add(new ClassTypeInfoManagerDB(this, (ProgramDB) program));
	}

	@Override
	protected void programClosed(Program program) {
		managers.remove(getManager(program));
	}

	@Override
	protected void programActivated(Program program) {
		ClassTypeInfoManager manager = getManager(program);
		managerAdded(manager);
	}

	@Override
	protected void programDeactivated(Program program) {
		ClassTypeInfoManager manager = getManager(program);
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerClosed(manager)));
	}

	public Clipboard getClipboard() {
		return clipboard;
	}

	public DataTypeManagerPlugin getDataTypeManagerPlugin() {
		return dtmPlugin;
	}

	public DataTypeManagerHandler getDataTypeManagerHandler() {
		return dtmPlugin.getDataTypeManagerHandler();
	}

	public void fireArchiveChanged(TypeInfoArchiveChangeRecord record) {
		switch (record.getChangeType()) {
			case TYPE_ADDED:
				SystemUtilities.runSwingLater(
					() -> listeners.forEach(l -> l.typeAdded(record.getType())));
				break;
			case TYPE_REMOVED:
				SystemUtilities.runSwingLater(
					() -> listeners.forEach(l -> l.typeRemoved(record.getType())));
				break;
			case TYPE_UPDATED:
				// running now will cause deadlock
				SystemUtilities.runSwingLater(
					() -> listeners.forEach(l -> l.typeUpdated(record.getType())));
				break;
		}
	}

	@Override
	public ProgramClassTypeInfoManager getManager(Program program) {
		if (managers.isEmpty()) {
			return null;
		}
		return managers.stream()
				.filter(ProgramClassTypeInfoManager.class::isInstance)
				.map(ProgramClassTypeInfoManager.class::cast)
				.filter(m -> m.getProgram().equals(program))
				.findAny()
				.orElseThrow();
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

	public TypeInfoTreeProvider getProvider() {
		return provider;
	}

	public void goTo(TypeInfoNode node) {
		Address address = node.getAddress();
		if (address != null) {
			goTo(address);
		}
	}

	@Override
	public GTree getTree() {
		return provider.getTree();
	}

	@Override
	public void managerAdded(ClassTypeInfoManager manager) {
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerOpened(manager)));
	}

	@Override
	public void archiveOpened(Archive archive) {
		ClassTypeInfoManager manager = null;
		try {
			if (archive instanceof FileArchive) {
				manager = ArchiveClassTypeInfoManager.openIfManagerArchive(this, archive);
			} else if (archive instanceof ProjectArchive) {
				manager = ProjectClassTypeInfoManager.openIfManagerArchive(this, archive);
			}
		} catch (IOException e) {
			Msg.error(manager, e);
		}
		if (manager != null) {
			managerAdded(manager);
			managers.add(manager);
		}
	}

	private ClassTypeInfoManager getManager(Archive archive) {
		return managers.stream()
			.filter(FileArchiveClassTypeInfoManager.class::isInstance)
			.filter(m -> m.getName().equals(archive.getName()))
			.findFirst()
			.orElse(null);
	}

	@Override
	public void archiveClosed(Archive archive) {
		ClassTypeInfoManager manager = getManager(archive);
		if (manager != null) {
			managers.remove(manager);
			SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerClosed(manager)));
		}
	}

	@Override
	public void archiveStateChanged(Archive archive) {
	}

	@Override
	public void archiveDataTypeManagerChanged(Archive archive) {
	}

	@Override
	public ArchivedClassTypeInfo getExternalClassTypeInfo(Program program, String mangled) {
		String[] libs = program.getExternalManager().getExternalLibraryNames();
		List<LibraryClassTypeInfoManager> libManagers = managers.stream()
			.filter(ProjectClassTypeInfoManager.class::isInstance)
			.map(ProjectClassTypeInfoManager.class::cast)
			.flatMap(m -> m.getAvailableManagers(libs))
			.collect(Collectors.toList());
		for (LibraryClassTypeInfoManager manager : libManagers) {
			ArchivedClassTypeInfo type = manager.getType(mangled);
			if (type != null) {
				return type;
			}
		}
		throw new UnresolvedClassTypeInfoException(program, mangled);
	}
}