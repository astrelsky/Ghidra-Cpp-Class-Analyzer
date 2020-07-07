package cppclassanalyzer.plugin.typemgr.action;

import java.awt.event.KeyEvent;

import docking.ActionContext;

final class CopyArchiveAction extends AbstractArchiveClipboardAction {

	public CopyArchiveAction(TypeInfoArchiveHandler handler) {
		super("Copy", KeyEvent.VK_C, handler);
	}

	@Override
	public final String getDescription() {
		return "Copy Archive";
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return !getSelectedRootTreeNodes(context).isEmpty();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		setClipboardContents(getTree(), getSelectedRootTreeNodes(context));
	}
}
