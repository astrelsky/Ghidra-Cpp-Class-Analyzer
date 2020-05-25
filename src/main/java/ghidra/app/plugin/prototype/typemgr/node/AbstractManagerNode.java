package ghidra.app.plugin.prototype.typemgr.node;

import java.util.ArrayList;
import java.util.List;

import javax.help.UnsupportedOperationException;
import javax.swing.Icon;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;

abstract class AbstractManagerNode extends GTreeSlowLoadingNode implements TypeInfoTreeNode {

	private final ClassTypeInfoManager manager;
	private final TypeInfoTreeNodeRecord record;

	AbstractManagerNode(ClassTypeInfoManager manager) {
		this.manager = manager;
		this.record = getManager().getRootRecord();
	}

	@Override
	public GTreeNode clone() {
		return this;
	}

	@Override
	public final List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		TypeInfoTreeNodeManager treeManager = getManager();
		long[] keys = getRecord().getLongArray(TypeInfoTreeNodeSchemaFields.CHILDREN_KEYS);
		List<GTreeNode> children = new ArrayList<>(keys.length);
		monitor.initialize(keys.length);
		for (long key : keys) {
			monitor.checkCanceled();
			TypeInfoTreeNodeRecord child = treeManager.getRecord(key);
			children.add(treeManager.getNode(child));
			monitor.incrementProgress(1);
		}
		return children;
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
}