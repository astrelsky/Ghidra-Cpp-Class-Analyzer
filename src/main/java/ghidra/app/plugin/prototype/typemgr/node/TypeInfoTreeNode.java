package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import docking.widgets.tree.GTreeNode;

public interface TypeInfoTreeNode {
	long getKey();
	TypeInfoTreeNodeRecord getRecord();
	TypeInfoTreeNodeManager getManager();
	void setParent(long key);

	default GTreeNode getNode() {
		return (GTreeNode) this;
	}
}