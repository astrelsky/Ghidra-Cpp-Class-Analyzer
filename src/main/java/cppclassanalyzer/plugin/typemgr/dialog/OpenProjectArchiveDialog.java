package cppclassanalyzer.plugin.typemgr.dialog;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.app.util.HelpTopics;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;

import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;

public class OpenProjectArchiveDialog extends OpenVersionedFileDialog<DataTypeArchive> {

	private static final HelpLocation HELP_LOCATION =
		new HelpLocation(HelpTopics.PROGRAM, "Open_File_Dialog");

	private final ClassTypeInfoManagerPlugin plugin;

	public OpenProjectArchiveDialog(ClassTypeInfoManagerPlugin plugin) {
		super(plugin.getTool(), "Open Project Data Type Archive", DataTypeArchive.class);
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
			if (domainFile == null) {
				setStatusText("Please choose a Project Data Type Archive");
			}
			else {
				close();
				DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
				try {
					ProjectArchive archive = (ProjectArchive) handler.openArchive(
						domainFile, true, false, getTaskMonitorComponent());
					plugin.openProjectArchive(archive);
				} catch (Exception e) {
					setStatusText(e.getMessage(), MessageType.ERROR);
				}
			}
		}
	}
}
