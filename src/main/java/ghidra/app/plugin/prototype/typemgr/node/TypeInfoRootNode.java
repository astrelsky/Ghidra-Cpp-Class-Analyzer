package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
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

	@Override
	public int compareTo(GTreeNode node) {
		if (getTypeManager() instanceof ProgramClassTypeInfoManager) {
			return -1;
		}
		if (node instanceof ProjectArchiveTypeInfoNode) {
			return 1;
		}
		return super.compareTo(node);
	}

	@Override
	TypeInfoRootNode rebuild() {
		ClassTypeInfoManager manager = (ClassTypeInfoManager) getTypeManager();
		GTreeNode parent = getParent();
		parent.removeNode(this);
		TypeInfoRootNode result = new TypeInfoRootNode(manager);
		parent.addNode(result);
		return result;
	}

}