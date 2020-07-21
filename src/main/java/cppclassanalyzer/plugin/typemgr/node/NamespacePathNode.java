package cppclassanalyzer.plugin.typemgr.node;

import javax.swing.Icon;

import ghidra.app.plugin.core.symboltree.nodes.NamespaceSymbolNode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import docking.widgets.tree.GTreeNode;

import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

import java.util.*;
import java.util.stream.Collectors;

public final class NamespacePathNode extends AbstractSortedSlowLoadingNode
		implements TypeInfoTreeNode {

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
	public void addNode(int index, GTreeNode node) {
		if (node instanceof TypeInfoTreeNode) {
			TypeInfoTreeNode treeNode = (TypeInfoTreeNode) node;
			long key = treeNode.getKey();
			long[] children = record.getLongArray(CHILDREN_KEYS);
			if (Arrays.binarySearch(children, key) < 0) {
				Set<Long> kids = Arrays.stream(children)
					.boxed()
					.collect(Collectors.toCollection(TreeSet::new));
				kids.add(key);
				children = kids.stream()
					.mapToLong(Long::longValue)
					.toArray();
				record.setLongArray(CHILDREN_KEYS, children);
				getManager().updateRecord(record);
			}
		}
		super.addNode(index, node);
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
