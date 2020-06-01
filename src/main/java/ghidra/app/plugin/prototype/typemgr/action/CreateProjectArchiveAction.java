package ghidra.app.plugin.prototype.typemgr.action;

import java.io.IOException;

import ghidra.util.Msg;

import docking.ActionContext;

final class CreateProjectArchiveAction extends AbstractTypeMgrAction {

	CreateProjectArchiveAction(TypeInfoArchiveHandler handler) {
		super("Create Project Archive", handler);
		setMenuBar();
	}

	@Override
	public String getDescription() {
		return "Creates a new project type info archive";
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			getHandler().getPlugin().createProjectArchive();
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}
}
