package ghidra.app.plugin.prototype.typemgr.actions;

import java.io.File;
import java.io.IOException;

import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.TypeInfoTreeProvider;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.tree.GTree;

public class OpenArchiveAction extends DockingAction {

	private final static String EXTENSION = "cdb";
	private final ClassTypeInfoManagerPlugin plugin;

	public OpenArchiveAction(ClassTypeInfoManagerPlugin plugin) {
		super("Open File Type Info Archive", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { "Open File Archive..." }, "Archive"));

		setDescription("Opens a data type archive in this data type manager.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		TypeInfoTreeProvider provider = plugin.getProvider();
		GTree tree = provider.getTree();
		GhidraFileChooser fileChooser = new GhidraFileChooser(tree);

		File archiveDirectory = CppClassAnalyzerPreferences.getLastOpenedArchivePath();
		fileChooser.setFileFilter(new ExtensionFileFilter(
			new String[] { EXTENSION }, "Ghidra Type Info Archive Files"));
		fileChooser.setCurrentDirectory(archiveDirectory);
		fileChooser.setApproveButtonText("Open Type Info Archive File");
		fileChooser.setApproveButtonToolTipText("Open Type Info Archive File");

		File file = fileChooser.getSelectedFile();
		if (file == null || !file.exists()) {
			return;
		}

		File lastOpenedDir = file.getParentFile();
		CppClassAnalyzerPreferences.setLastOpenedArchivePath(lastOpenedDir);

		try {
			plugin.openArchive(file);
		} catch (IOException e) {
			Msg.showError(plugin, null, "Failed to open Type Info Archive", e);
		}
	}
}
