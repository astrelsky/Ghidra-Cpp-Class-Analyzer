package ghidra.app.plugin.prototype.typemgr.action;

import java.awt.event.KeyEvent;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.plugin.prototype.typemgr.node.TypeInfoArchiveNode;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import docking.ActionContext;

final class PasteArchiveAction extends AbstractArchiveClipboardAction {

	private static final String NAME = "Paste";
	private static final String DESCRIPTION = "Paste Archive";

	PasteArchiveAction(TypeInfoArchiveHandler handler) {
		super(NAME, KeyEvent.VK_V, handler);
	}

	@Override
	public final String getDescription() {
		return DESCRIPTION;
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
		PasteArchiveTask task = new PasteArchiveTask(manager, srcManagers);
		tool.execute(task);
	}

	private static final class PasteArchiveTask extends Task {

		private final ProjectClassTypeInfoManager manager;
		private final List<ClassTypeInfoManager> srcManagers;

		public PasteArchiveTask(ProjectClassTypeInfoManager manager,
				List<ClassTypeInfoManager> srcManagers) {
			super("Paste Archive", true, true, true);
			this.manager = manager;
			this.srcManagers = srcManagers;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			manager.insert(srcManagers, monitor);
		}

	}

}