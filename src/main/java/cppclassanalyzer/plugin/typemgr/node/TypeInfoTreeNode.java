package cppclassanalyzer.plugin.typemgr.node;

import docking.widgets.tree.GTreeNode;

public interface TypeInfoTreeNode {

	public TypeInfoTreeNodeManager getManager();

	default GTreeNode getNode() {
		return (GTreeNode) this;
	}
}
