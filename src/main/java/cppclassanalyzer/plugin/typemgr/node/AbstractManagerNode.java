package cppclassanalyzer.plugin.typemgr.node;

import javax.swing.Icon;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

abstract class AbstractManagerNode extends AbstractSortedNode implements TypeInfoArchiveNode {

	private final ClassTypeInfoManager manager;

	AbstractManagerNode(ClassTypeInfoManager manager) {
		this.manager = manager;
	}

	@Override
	public final GTreeNode clone() {
		return this;
	}

	@Override
	public final String getName() {
		return manager.getName();
	}

	@Override
	public final Icon getIcon(boolean expanded) {
		return manager.getIcon(expanded);
	}

	@Override
	public final boolean isLeaf() {
		return false;
	}

	@Override
	public final String getToolTip() {
		return null;
	}

	@Override
	public ClassTypeInfoManager getTypeManager() {
		return manager;
	}

	@Override
	public TypeInfoTreeNodeManager getManager() {
		return manager.getTreeNodeManager();
	}

	@Override
	public final boolean isProgramNode() {
		return getTypeManager() instanceof ProgramClassTypeInfoManager;
	}

	@Override
	public GTree getTree() {
		GTree tree = super.getTree();
		if (tree == null) {
			// circumvent race condition it'll get set eventually
			// all tasks requiring the tree end up in the end of the swing queue
			if (isProgramNode()) {
				ProgramClassTypeInfoManager manager =
					(ProgramClassTypeInfoManager) getTypeManager();
				tree = CppClassAnalyzerUtils.getService(manager.getProgram()).getTree();
			}
		}
		return tree;
	}
}
