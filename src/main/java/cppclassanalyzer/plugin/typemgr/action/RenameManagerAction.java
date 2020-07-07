package cppclassanalyzer.plugin.typemgr.action;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.KeyBindingPrecedence;
import docking.action.KeyBindingData;
import docking.widgets.tree.GTreeNode;

public class RenameManagerAction extends AbstractFileArchivePopupAction {

    private static final KeyBindingData KEY_BINDING =
        new KeyBindingData(KeyStroke.getKeyStroke("F2"), KeyBindingPrecedence.ActionMapLevel);

	RenameManagerAction(TypeInfoArchiveHandler handler) {
        super("Rename", handler);
        setKeyBindingData(KEY_BINDING);
	}

	@Override
	MenuGroupType getGroup() {
		return MenuGroupType.EDIT;
    }

    @Override
    public boolean isAddToPopup(ActionContext context) {
        GTreeNode node = (GTreeNode) getSelectedNode(context);
        if (node != null) {
            return node.isEditable();
        }
        return false;
    }

	@Override
	public void actionPerformed(ActionContext context) {
        GTreeNode node = (GTreeNode) getSelectedNode(context);
		node.getTree().startEditing(node.getParent(), node.getName());
    }

}
