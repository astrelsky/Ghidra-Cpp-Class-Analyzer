package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;

interface TypeInfoTreeNode {
	long getKey();
	TypeInfoTreeNodeRecord getRecord();
	TypeInfoTreeNodeManager getManager();
	void setParent(long key);
}