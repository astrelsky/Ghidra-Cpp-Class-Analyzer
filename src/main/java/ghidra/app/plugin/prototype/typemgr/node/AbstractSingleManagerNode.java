package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import docking.widgets.tree.GTreeNode;

import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

abstract class AbstractSingleManagerNode extends AbstractManagerNode {

	AbstractSingleManagerNode(ClassTypeInfoManager manager) {
		super(manager);
	}

	@Override
	public final void addNode(GTreeNode node) {
		if (node instanceof TypeInfoTreeNode) {
			TypeInfoTreeNode treeNode = (TypeInfoTreeNode) node;
			TypeInfoTreeNodeRecord record = getRecord();
			long[] children = record.getLongArray(CHILDREN_KEYS);
			long[] newChildren = new long[children.length + 1];
			System.arraycopy(children, 0, newChildren, 0, children.length);
			newChildren[children.length] = treeNode.getKey();
			record.setLongArray(CHILDREN_KEYS, newChildren);
			getManager().updateRecord(record);
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
	public final void addNode(ClassTypeInfoDB type) {
		List<String> paths = type.getSymbolPath().asList();
		GTreeNode node = this;
		TypeInfoTreeNodeManager treeManager = getManager();
		for (int i = 0; i < paths.size(); i++) {
			String path = paths.get(i);
			GTreeNode currentNode = node.getChild(path);
			if (currentNode == null) {
				List<String> subPaths = paths.subList(0, i+1);
				if (subPaths.size() == paths.size()) {
					currentNode = treeManager.createTypeNode(subPaths, type);
				} else {
					currentNode = treeManager.createNamespaceNode(subPaths);
				}
				node.addNode(currentNode);
			}
			node = currentNode;
		}
		if (node instanceof NamespacePathNode) {
			GTreeNode parent = node.getParent();
			parent.removeNode(node);
			TypeInfoTreeNodeRecord record = ((TypeInfoTreeNode) node).getRecord();
			node.dispose();
			record.setByteValue(TYPE_ID, TypeInfoTreeNodeRecord.TYPEINFO_NODE);
			record.setLongValue(TYPE_KEY, type.getKey());
			treeManager.updateRecord(record);
			GTreeNode currentNode = new TypeInfoNode(type, record);
			parent.addNode(currentNode);
		}
		children().sort(null);
	}

	@Override
	public final TypeInfoNode getNode(ClassTypeInfoDB type) {
		TypeInfoTreeNodeManager treeManager = getManager();
		SymbolPath path = type.getSymbolPath();
		GTreeNode node = treeManager.getNode(path);
		if (node instanceof TypeInfoNode) {
			return (TypeInfoNode) node;
		}
		if (node == null) {
			throw new AssertException("Node for "+type.getName()+" not found");
		}
		throw new AssertException("Node for "+type.getName()+" is not the correct node type");
	}
}