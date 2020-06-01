package ghidra.app.plugin.prototype.typemgr.action;

import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;

final class OpenProjectArchiveAction extends AbstractTypeMgrAction {

	OpenProjectArchiveAction(TypeInfoArchiveHandler handler) {
		super("Open Project Archive", handler);
		setMenuBar();
	}

	@Override
	public String getDescription() {
		return "Opens an existing project type info archive";
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			getHandler().getPlugin().openProjectArchive();
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}
}
