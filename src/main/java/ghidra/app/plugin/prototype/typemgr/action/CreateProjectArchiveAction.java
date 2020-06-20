package ghidra.app.plugin.prototype.typemgr.action;

import java.io.IOException;

import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ArchiveManagerListener;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.util.Msg;
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
			ProjectArchiveCreator creator = new ProjectArchiveCreator();
			getDataTypeManagerHandler().createProjectArchive();
			creator.open();
		} catch (CancelledException e) {
		}
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.ARCHIVE;
	}

	private class ProjectArchiveCreator implements ArchiveManagerListener {

		private ProjectArchive archive;

		ProjectArchiveCreator() {
			getDataTypeManagerHandler().addArchiveManagerListener(this);
		}

		void open() {
			if (archive != null) {
				getDataTypeManagerHandler().removeArchiveManagerListener(this);
				getDataTypeManagerHandler().save(archive.getDomainObject());
				if (!getHandler().getPlugin().hasManager(archive)) {
					getHandler().getPlugin().archiveOpened(archive);
				}
			}
		}

		@Override
		public void archiveOpened(Archive archive) {
			if (archive instanceof ProjectArchive) {
				try {
					ProjectClassTypeInfoManager.init((ProjectArchive) archive);
					this.archive = (ProjectArchive) archive;
				} catch (IOException e) {
					Msg.error(this, e);
				}
			}
		}

		@Override
		public void archiveClosed(Archive archive) {
		}

		@Override
		public void archiveStateChanged(Archive archive) {
		}

		@Override
		public void archiveDataTypeManagerChanged(Archive archive) {
		}

	}
}
