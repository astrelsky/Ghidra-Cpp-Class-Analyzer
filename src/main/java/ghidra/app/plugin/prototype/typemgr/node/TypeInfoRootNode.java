package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;

import docking.widgets.tree.GTreeNode;

public final class TypeInfoRootNode extends AbstractSingleManagerNode {

	public TypeInfoRootNode(ClassTypeInfoManager manager) {
		super(manager);
	}

	public void removeNode(ClassTypeInfoDB type) {
		GTreeNode node = (GTreeNode) getNode(type);
		if (node != null) {
			removeNode(node);
		}
	}

}