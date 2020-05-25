package ghidra.app.plugin.prototype.typemgr.dialog;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.filter.ProjectArchiveFilter;
import ghidra.app.util.HelpTopics;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

public class OpenProjectArchiveDialog extends OpenVersionedFileDialog {

	private static final HelpLocation HELP_LOCATION =
		new HelpLocation(HelpTopics.PROGRAM, "Open_File_Dialog");

	private final ClassTypeInfoManagerPlugin plugin;

	public OpenProjectArchiveDialog(ClassTypeInfoManagerPlugin plugin) {
		super(plugin.getTool(), "Open Project Data Type Archive", ProjectArchiveFilter.FILTER);
		this.plugin = plugin;
		setHelpLocation(HELP_LOCATION);
		addOkActionListener(new ProjectArchiveActionListener());
	}

	public void show() {
		plugin.getTool().showDialog(this);
	}

	private class ProjectArchiveActionListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent event) {
			DomainFile domainFile = getDomainFile();
			int version = getVersion();
			if (domainFile == null) {
				setStatusText("Please choose a Project Data Type Archive");
			}
			else {
				close();
				DataTypeManagerPlugin dtmPlugin = plugin.getDataTypeManagerPlugin();
				DataTypeArchiveDB archive =
					(DataTypeArchiveDB) dtmPlugin.openArchive(domainFile, version);
				try {
					plugin.openProjectArchive(archive);
				} catch (IOException e) {
					// shouldn't happen, already open
					throw new AssertException(e);
				}
			}
		}
	}
}