package ghidra.app.plugin.prototype.typemgr.action;

import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

class CreateProjectArchiveAction extends DockingAction {

	private final TypeInfoArchiveHandler handler;

	CreateProjectArchiveAction(TypeInfoArchiveHandler handler) {
		super("Create Project Type Info Archive", handler.getPlugin().getName());
		this.handler = handler;

		setMenuBarData(new MenuData(new String[] { "Create Project Archive..." }, "Archive"));

		setDescription("Creates a new project type info archive.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			handler.getPlugin().createProjectArchive();
		} catch (IOException e) {
			Msg.showError(handler, null, "Failed to create Type Info Archive", e);
		}
	}
}
