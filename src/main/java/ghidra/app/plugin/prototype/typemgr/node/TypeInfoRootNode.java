package ghidra.app.plugin.prototype.typemgr.node;

import java.util.List;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.util.SymbolPath;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;

import ghidra.util.exception.AssertException;

import docking.widgets.tree.GTreeNode;

import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

public class TypeInfoRootNode extends AbstractManagerNode {

	public TypeInfoRootNode(ClassTypeInfoManager manager) {
		super(manager);
	}

	@Override
	public String getToolTip() {
		return null;
	}

	public boolean isProgramNode() {
		return getTypeManager() instanceof ProgramClassTypeInfoManager;
	}

	public void addNode(ClassTypeInfoDB type) {
		List<String> paths = type.getSymbolPath().asList();
		GTreeNode node = this;
		for (int i = 0; i < paths.size(); i++) {
			String path = paths.get(i);
			GTreeNode currentNode = node.getChild(path);
			if (currentNode == null) {
				List<String> subPaths = paths.subList(0, i+1);
				if (subPaths.size() == paths.size()) {
					currentNode = createTypeNode(subPaths, type);
				} else {
					currentNode = createNamespaceNode(subPaths);
				}
				node.addNode(currentNode);
			}
			node = currentNode;
		}
		if (node instanceof NamespacePathNode) {
			GTreeNode parent = node.getParent();
			parent.removeNode(node);
			GTreeNode currentNode = createNestedNode(type, (NamespacePathNode) node);
			currentNode.addNode(node);
			parent.addNode(currentNode);
		}
		children().sort(null);
	}

	private GTreeNode createNamespaceNode(List<String> paths) {
		TypeInfoTreeNodeManager treeManager = getTypeManager().getTreeNodeManager();
		TypeInfoTreeNodeRecord record =
			treeManager.createRecord(paths, TypeInfoTreeNodeRecord.NAMESPACE_NODE);
		return new NamespacePathNode(treeManager, record);
	}

	private GTreeNode createTypeNode(List<String> paths, ClassTypeInfoDB type) {
		TypeInfoTreeNodeManager treeManager = getTypeManager().getTreeNodeManager();
		TypeInfoTreeNodeRecord record =
			treeManager.createRecord(paths, TypeInfoTreeNodeRecord.TYPEINFO_NODE);
		record.setLongValue(TYPE_KEY, type.getKey());
		treeManager.updateRecord(record);
		return new TypeInfoNode(type, record);
	}

	private GTreeNode createNestedNode(ClassTypeInfoDB type, NamespacePathNode nested) {
		TypeInfoTreeNodeRecord record = nested.getRecord();
		record.setByteValue(TYPE_ID, TypeInfoTreeNodeRecord.NESTED_NODE);
		record.setLongValue(TYPE_KEY, type.getKey());
		getTypeManager().getTreeNodeManager().updateRecord(record);
		return new TypeInfoNode(type, nested, record);
	}



	public void removeNode(ClassTypeInfo type) {
		GTreeNode node = getNode(type);
		if (node != null) {
			removeNode(node);
		}
	}

	public TypeInfoNode getNode(ClassTypeInfo type) {
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