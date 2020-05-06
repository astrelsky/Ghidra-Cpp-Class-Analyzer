package ghidra.app.plugin.prototype;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;
import ghidra.program.model.data.DataTypeManagerChangeListener;
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
	servicesProvided = { ClassTypeInfoManagerService.class }
)
//@formatter:on
public class ClassTypeInfoManagerPlugin extends ProgramPlugin
		implements ClassTypeInfoManagerService, DomainObjectListener, PopupActionProvider {

	private final Map<Program, ClassTypeInfoManager> managers;

	public ClassTypeInfoManagerPlugin(PluginTool tool) {
		super(tool, true, true);
		this.managers = new HashMap<>();
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener) {
		// TODO Auto-generated method stub

	}

	@Override
	public void removeClassTypeInfoManagerChangeListener(DataTypeManagerChangeListener listener) {
		// TODO Auto-generated method stub

	}

	@Override
	public void closeArchive(ClassTypeInfoManager manager) {
		// TODO Auto-generated method stub

	}

	@Override
	public ClassTypeInfoManager openClassTypeInfoArchive(String archiveName)
			throws IOException, DuplicateIdException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void programOpened(Program program) {
		program.addListener(this);
		managers.put(program, new ClassTypeInfoManagerDB((ProgramDB) program));
	}

	@Override
	protected void programClosed(Program program) {
		program.removeListener(this);
		managers.remove(program);
	}

	@Override
	public ClassTypeInfoManager getManager(Program program) {
		return managers.get(program);
	}
}