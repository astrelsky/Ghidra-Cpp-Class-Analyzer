package ghidra.app.plugin.prototype.typemgr;

import javax.swing.Icon;

import ghidra.app.plugin.core.symboltree.nodes.NamespaceSymbolNode;

import docking.widgets.tree.GTreeNode;

final class NamespacePathNode extends GTreeNode {

	private final String name;
	private String tip;

	NamespacePathNode(String name) {
		this.name = name;
	}

	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		return super.clone();
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof TypeInfoNode) {
			return -1;
		}
		return super.compareTo(node);
	}

	@Override
	public String getName() {
		return name;
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
	public boolean isLeaf() {
		return false;
	}

	@Override
	public void addNode(GTreeNode node) {
		super.addNode(node);
		children().sort(null);
	}

}