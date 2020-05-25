package ghidra.app.plugin.prototype.typemgr.action;

import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

class OpenProjectArchiveAction extends DockingAction {

	private final TypeInfoArchiveHandler handler;

	OpenProjectArchiveAction(TypeInfoArchiveHandler handler) {
		super("Open Project Type Info Archive", handler.getPlugin().getName());
		this.handler = handler;

		setMenuBarData(new MenuData(new String[] { "Open Project Archive..." }, "Archive"));

		setDescription("Opens an existing project type info archive.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			handler.getPlugin().openProjectArchive();
		} catch (IOException e) {
			Msg.showError(handler, null, "Failed to open Type Info Archive", e);
		}
	}
}
