package cppclassanalyzer.plugin.typemgr.action;

import java.io.IOException;

import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
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
			ProjectArchive archive =
				(ProjectArchive) getDataTypeManagerHandler().createProjectArchive();
			ProjectClassTypeInfoManager.init((ProjectArchive) archive);
			getDataTypeManagerHandler().save(archive.getDomainObject());
			getHandler().getPlugin().archiveOpened(archive);
		} catch(IOException e) {
			throw new AssertException(e);
		} catch (CancelledException e) {
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}
}
