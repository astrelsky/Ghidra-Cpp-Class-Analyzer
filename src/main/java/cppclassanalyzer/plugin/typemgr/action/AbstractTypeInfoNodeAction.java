package cppclassanalyzer.plugin.typemgr.action;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoNode;

import docking.ActionContext;

abstract class AbstractTypeInfoNodeAction extends AbstractTypeMgrAction {

	AbstractTypeInfoNodeAction(String name, TypeInfoArchiveHandler handler) {
		super(name, handler);
		setPopupMenu();
	}

	@Override
	final TypeInfoNode getSelectedNode(ActionContext context) {
		return getHandler().getTypeInfoNode(context);
	}

}
