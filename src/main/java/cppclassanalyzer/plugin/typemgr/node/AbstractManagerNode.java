package cppclassanalyzer.plugin.typemgr.node;

import javax.swing.Icon;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;

import docking.widgets.tree.GTreeNode;

abstract class AbstractManagerNode extends AbstractSortedSlowLoadingNode
		implements TypeInfoArchiveNode {

	private final ClassTypeInfoManager manager;
	private final TypeInfoTreeNodeRecord record;

	AbstractManagerNode(ClassTypeInfoManager manager) {
		this.manager = manager;
		TypeInfoTreeNodeManager treeManager = getManager();
		this.record = treeManager.getRootRecord();
		treeManager.setRootNode(this);
		// force generate now to prevent deadlock
		children();
	}

	abstract AbstractManagerNode rebuild();

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
	public long getKey() {
		return 0;
	}

	@Override
	public TypeInfoTreeNodeRecord getRecord() {
		return record;
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
	public void dispose() {
		getManager().dispose();
		super.dispose();
	}
}
