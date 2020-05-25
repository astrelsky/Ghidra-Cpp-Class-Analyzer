package ghidra.app.plugin.prototype.typemgr.node;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import ghidra.app.plugin.core.symboltree.nodes.NamespaceSymbolNode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;

import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

public final class NamespacePathNode extends GTreeSlowLoadingNode implements TypeInfoTreeNode {

	private final TypeInfoTreeNodeManager manager;
	private final TypeInfoTreeNodeRecord record;
	private final String name;
	private List<GTreeNode> kids;
	private String tip;

	NamespacePathNode(TypeInfoTreeNodeManager manager, TypeInfoTreeNodeRecord record) {
		this.manager = manager;
		this.record = record;
		this.name = record.getStringValue(NAME);
	}

	@Override
	public void setParent(long key) {
		record.setLongValue(PARENT_KEY, key);
		manager.updateRecord(record);
	}

	@Override
	public void addNode(GTreeNode node) {
		if (kids == null) {
			kids = new ArrayList<>();
		}
		if (node instanceof TypeInfoTreeNode) {
			TypeInfoTreeNode treeNode = (TypeInfoTreeNode) node;
			long[] children = record.getLongArray(CHILDREN_KEYS);
			long[] newChildren = new long[children.length + 1];
			System.arraycopy(children, 0, newChildren, 0, children.length);
			newChildren[children.length] = treeNode.getKey();
			record.setLongArray(CHILDREN_KEYS, newChildren);
			manager.updateRecord(record);
			treeNode.setParent(getKey());
		}
		kids.add(node);
		super.addNode(node);
		children().sort(null);
	}

	@Override
	public final GTreeNode clone() {
		return this;
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof TypeInfoNode) {
			return -1;
		}
		return super.compareTo(node);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return NamespaceSymbolNode.NAMESPACE_ICON;
	}

	@Override
	public String getToolTip() {
		return tip;
	}

	void setToolTip(String tip) {
		this.tip = tip;
	}

	@Override
	public long getKey() {
		return record.getKey();
	}

	@Override
	public TypeInfoTreeNodeRecord getRecord() {
		return record;
	}

	@Override
	public TypeInfoTreeNodeManager getManager() {
		return manager;
	}

	@Override
	public final List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		TypeInfoTreeNodeManager treeManager = getManager();
		long[] keys = getRecord().getLongArray(CHILDREN_KEYS);
		kids = new ArrayList<>(keys.length);
		monitor.initialize(keys.length);
		for (long key : keys) {
			monitor.checkCanceled();
			TypeInfoTreeNodeRecord child = treeManager.getRecord(key);
			kids.add(treeManager.getNode(child));
			monitor.incrementProgress(1);
		}
		return kids;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isLeaf() {
		return kids == null || kids.isEmpty();
	}

}