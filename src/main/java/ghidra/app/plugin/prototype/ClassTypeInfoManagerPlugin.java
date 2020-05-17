package ghidra.app.plugin.prototype;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.prototype.typemgr.AddressableTreeNode;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;
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
import ghidra.program.database.data.rtti.manager.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.manager.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

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
	private final List<TypeInfoManagerListener> listeners;
	private final TypeInfoTreeProvider provider;

	public ClassTypeInfoManagerPlugin(PluginTool tool) {
		super(tool, true, true);
		plugins.add(this);
		this.listeners = new ArrayList<>();
		this.managers = new ArrayList<>();
		this.provider = new TypeInfoTreeProvider(tool, this);
	}

	@Override
	public List<ClassTypeInfoManager> getManagers() {
		return Collections.unmodifiableList(managers);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		// TODO Auto-generated method stub
		return Collections.emptyList();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// do nothing
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
	public void closeArchive(ClassTypeInfoManager manager) {
		managers.remove(manager);
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerClosed(manager)));
		if (manager instanceof StandAloneDataTypeManager) {
			((StandAloneDataTypeManager) manager).close();
		}
	}

	@Override
	public ClassTypeInfoManager openArchive(File file, boolean updateable) throws IOException {
		ClassTypeInfoManager manager = ArchiveClassTypeInfoManager.open(this, file, updateable);
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerOpened(manager)));
		return manager;
	}

	@Override
	public ClassTypeInfoManager createArchive(File file) throws IOException {
		ClassTypeInfoManager manager = ArchiveClassTypeInfoManager.createManager(this, file);
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerOpened(manager)));
		return manager;
	}

	@Override
	protected void programOpened(Program program) {
		program.addListener(this);
		managers.add(new ClassTypeInfoManagerDB(this, (ProgramDB) program));
	}

	@Override
	protected void programClosed(Program program) {
		program.removeListener(this);
		managers.remove(getManager(program));
	}

	@Override
	protected void programActivated(Program program) {
		ClassTypeInfoManager manager = getManager(program);
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerOpened(manager)));
	}

	@Override
	protected void programDeactivated(Program program) {
		ClassTypeInfoManager manager = getManager(program);
		SystemUtilities.runSwingNow(() -> listeners.forEach(l -> l.managerClosed(manager)));
	}

	public void fireArchiveChanged(TypeInfoArchiveChangeRecord record) {
		switch(record.getChangeType()) {
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
			default:
				throw new AssertException("Unknown change type");
		}
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
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

	public TypeInfoTreeProvider getProvider() {
		return provider;
	}

	public void goTo(AddressableTreeNode node) {
		if (node.hasAddress()) {
			goTo(node.getAddress());
		}
	}
}