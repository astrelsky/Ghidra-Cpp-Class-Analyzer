package cppclassanalyzer.plugin.typemgr.node;

import java.util.Collections;
import java.util.List;

import docking.widgets.tree.GTreeNode;

abstract class AbstractSortedNode extends GTreeNode {

	@Override
	public final void addNode(GTreeNode node) {
		int index;
		synchronized (this) {
			List<GTreeNode> kids = children();
			index = Collections.binarySearch(kids, node);
		}
		if (index >= 0) {
			//String msg = "Child node "+node.getName()+" already exists in "+getName();
			//throw new AssertException(msg);
			//TODO fixme
			return;
		}
		addNode(-(index + 1), node);
	}

	@Override
	public String getToolTip() {
		return null;
	}
}
