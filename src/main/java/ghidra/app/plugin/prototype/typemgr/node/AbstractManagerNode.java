package ghidra.app.plugin.prototype.typemgr.node;

import javax.help.UnsupportedOperationException;
import javax.swing.Icon;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;

abstract class AbstractManagerNode extends GTreeSlowLoadingNode
		implements TypeInfoTreeNode, TypeInfoArchiveNode {

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
		return manager.getTypeCount() == 0;
	}

	@Override
	public final String getToolTip() {
		return null;
	}

	@Override
	public final ClassTypeInfoManager getTypeManager() {
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
	public void setParent(long key) {
		throw new UnsupportedOperationException("The root node cannot have a parent node");
	}

	@Override
	public final boolean isProgramNode() {
		return getTypeManager() instanceof ProgramClassTypeInfoManager;
	}
}