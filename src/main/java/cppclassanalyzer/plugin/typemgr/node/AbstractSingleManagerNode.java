package cppclassanalyzer.plugin.typemgr.node;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import docking.widgets.tree.GTreeNode;

import java.util.*;

import ghidra.app.util.SymbolPath;
import ghidra.util.Msg;

abstract class AbstractSingleManagerNode extends AbstractManagerNode {

	private final Map<SymbolPath, GTreeNode> treePaths;

	AbstractSingleManagerNode(ClassTypeInfoManager manager) {
		super(manager);
		this.treePaths = Collections.synchronizedMap(new HashMap<>(manager.getTypeCount()));
	}

	@Override
	public final void addNode(ClassTypeInfoDB type) {
		getManager().createTypeNode(type);
	}

	@Override
	public final TypeInfoNode getNode(ClassTypeInfoDB type) {
		SymbolPath path = type.getSymbolPath();
		if (!treePaths.containsKey(path)) {
			Msg.warn(this, "Node for "+type.getName()+" not found");
			addNode(type);
		}
		GTreeNode node = treePaths.get(path);
		if (node instanceof NamespacePathNode) {
			node = new TypeInfoNode(type, (NamespacePathNode) node);
		}
		return (TypeInfoNode) node;
	}
}
