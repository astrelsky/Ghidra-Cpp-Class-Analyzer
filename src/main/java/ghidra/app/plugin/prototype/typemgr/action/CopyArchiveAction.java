package ghidra.app.plugin.prototype.typemgr.action;

import java.awt.event.KeyEvent;

import docking.ActionContext;

final class CopyArchiveAction extends AbstractArchiveClipboardAction {

	private static final String NAME = "Copy";

	public CopyArchiveAction(TypeInfoArchiveHandler handler) {
		super(NAME, KeyEvent.VK_C, handler);
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