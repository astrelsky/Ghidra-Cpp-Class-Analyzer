package ghidra.app.plugin.prototype.typemgr.node;

import java.util.List;

import javax.help.UnsupportedOperationException;
import javax.swing.Icon;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;

import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.CHILDREN_KEYS;

abstract class AbstractManagerNode extends GTreeSlowLoadingNode implements TypeInfoTreeNode {

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
	public GTreeNode clone() {
		return this;
	}

	@Override
	public void addNode(GTreeNode node) {
		if (node instanceof TypeInfoTreeNode) {
			TypeInfoTreeNode treeNode = (TypeInfoTreeNode) node;
			long[] children = record.getLongArray(CHILDREN_KEYS);
			long[] newChildren = new long[children.length + 1];
			System.arraycopy(children, 0, newChildren, 0, children.length);
			newChildren[children.length] = treeNode.getKey();
			record.setLongArray(CHILDREN_KEYS, newChildren);
			manager.getTreeNodeManager().updateRecord(record);
			treeNode.setParent(getKey());
		}
		super.addNode(node);
		children().sort(null);
	}

	@Override
	public final List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		return getManager().generateChildren(this, monitor);
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