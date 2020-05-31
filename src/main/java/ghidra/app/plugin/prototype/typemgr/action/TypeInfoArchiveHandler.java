package ghidra.app.plugin.prototype.typemgr.action;

import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.TypeInfoArchiveGTree;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;

import docking.action.DockingAction;

public final class TypeInfoArchiveHandler {

	private final ClassTypeInfoManagerPlugin plugin;

	public TypeInfoArchiveHandler(ClassTypeInfoManagerPlugin plugin) {
		this.plugin = plugin;
	}

	TypeInfoTreeProvider getProvider() {
		return plugin.getProvider();
	}

	ClassTypeInfoManagerPlugin getPlugin() {
		return plugin;
	}

	ArchiveFileChooser getFileChooser() {
		return new ArchiveFileChooser(this);
	}

	TypeInfoArchiveGTree getTree() {
		return plugin.getProvider().getTree();
	}

	public DockingAction getCreateAction() {
		return new CreateArchiveAction(this);
	}

	public DockingAction getOpenAction() {
		return new OpenArchiveAction(this);
	}

	public DockingAction getCloseAction() {
		return new CloseArchiveAction(this);
	}

	public DockingAction getOpenForEditAction() {
		return new OpenForEditAction(this);
	}

	public DockingAction getSaveAction() {
		return new SaveAction(this);
	}

	public DockingAction getCreateProjectArchiveAction() {
		return new CreateProjectArchiveAction(this);
	}

	public DockingAction getOpenProjectArchiveAction() {
		return new OpenProjectArchiveAction(this);
	}

	public DockingAction getCopyArchiveAction() {
		return new CopyArchiveAction(this);
	}

	public DockingAction getPasteArchiveAction() {
		return new PasteArchiveAction(this);
	}
}