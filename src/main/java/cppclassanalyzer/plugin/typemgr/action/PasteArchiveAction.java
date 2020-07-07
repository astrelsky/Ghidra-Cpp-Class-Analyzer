package cppclassanalyzer.plugin.typemgr.action;

import java.awt.event.KeyEvent;
import java.util.List;
import java.util.stream.Collectors;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoArchiveNode;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import docking.ActionContext;

final class PasteArchiveAction extends AbstractArchiveClipboardAction {

	PasteArchiveAction(TypeInfoArchiveHandler handler) {
		super("Paste", KeyEvent.VK_V, handler);
	}

	@Override
	public final String getDescription() {
		return "Paste Archive";
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return getSelectedRootTreeNodes(context)
				.stream()
				.map(TypeInfoArchiveNode.class::cast)
				.map(TypeInfoArchiveNode::getTypeManager)
				.filter(ProjectClassTypeInfoManager.class::isInstance)
				.count() == 1;
	}

	private ProjectClassTypeInfoManager getSelectedManager(ActionContext context) {
		TypeInfoArchiveNode node = (TypeInfoArchiveNode) getSelectedRootTreeNodes(context).get(0);
		return (ProjectClassTypeInfoManager) node.getTypeManager();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		PluginTool tool = getHandler().getPlugin().getTool();
		ProjectClassTypeInfoManager manager = getSelectedManager(context);
		List<ClassTypeInfoManager> srcManagers = getClipboardContents()
				.stream()
				.map(TypeInfoArchiveNode.class::cast)
				.map(TypeInfoArchiveNode::getTypeManager)
				.collect(Collectors.toList());
		PasteArchiveBackgroundCommand cmd =
			new PasteArchiveBackgroundCommand(manager, srcManagers);
		manager.executeCommand(tool, cmd);
	}

	private static final class PasteArchiveBackgroundCommand extends BackgroundCommand {

		private final ProjectClassTypeInfoManager manager;
		private final List<ClassTypeInfoManager> srcManagers;

		public PasteArchiveBackgroundCommand(ProjectClassTypeInfoManager manager,
				List<ClassTypeInfoManager> srcManagers) {
			super("Paste Archive", true, true, true);
			this.manager = manager;
			this.srcManagers = srcManagers;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			try {
				manager.insert(srcManagers, monitor);
			} catch (CancelledException e) {
				setStatusMsg("Task cancelled");
				return false;
			}
			return true;
		}

	}

}
