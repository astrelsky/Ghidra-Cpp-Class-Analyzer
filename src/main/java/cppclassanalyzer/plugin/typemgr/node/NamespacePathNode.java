package cppclassanalyzer.plugin.typemgr.node;

import javax.swing.Icon;

import ghidra.app.plugin.core.symboltree.nodes.NamespaceSymbolNode;

import docking.widgets.tree.GTreeNode;

public final class NamespacePathNode extends AbstractSortedNode implements TypeInfoTreeNode {

	private final TypeInfoTreeNodeManager manager;
	private final String name;

	NamespacePathNode(String name, TypeInfoTreeNodeManager manager) {
		this.name = name;
		this.manager = manager;
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
