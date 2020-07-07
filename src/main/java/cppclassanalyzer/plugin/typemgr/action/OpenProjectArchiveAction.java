package cppclassanalyzer.plugin.typemgr.action;

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
		getHandler().getPlugin().getDataTypeManagerPlugin().openProjectDataTypeArchive();
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}
}
