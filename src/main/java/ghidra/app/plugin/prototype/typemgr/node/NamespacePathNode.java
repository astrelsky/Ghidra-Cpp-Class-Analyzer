package ghidra.app.plugin.prototype.typemgr.node;

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
	private final String tip;

	NamespacePathNode(TypeInfoTreeNodeManager manager, TypeInfoTreeNodeRecord record) {
		this.manager = manager;
		this.record = record;
		this.name = record.getStringValue(NAME);
		if (record.getByteValue(TYPE_ID) == TypeInfoTreeNodeRecord.TYPEINFO_NODE) {
			this.tip = "Nested Classes";
		} else {
			this.tip = null;
		}
		// force generate now to prevent deadlock
		children();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		return getManager().generateChildren(this, monitor);
	}

	@Override
	public void setParent(long key) {
		record.setLongValue(PARENT_KEY, key);
		manager.updateRecord(record);
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
			manager.updateRecord(record);
			treeNode.setParent(getKey());
		}
		super.addNode(node);
		children().sort(null);
	}

	@Override
	public GTreeNode clone() {
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
	public String getName() {
		return name;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

}