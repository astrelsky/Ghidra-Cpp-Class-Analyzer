package cppclassanalyzer.plugin.typemgr.node;

import java.util.Collections;
import java.util.List;

import ghidra.util.exception.AssertException;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;

abstract class AbstractSortedSlowLoadingNode extends GTreeSlowLoadingNode {

	@Override
	public final void addNode(GTreeNode node) {
		if (isLoaded()) {
			List<GTreeNode> kids = children();
			int index = Collections.binarySearch(kids, node);
			if (index >= 0) {
				String msg = "Child node "+node.getName()+" already exists in "+getName();
				throw new AssertException(msg);
			}
			addNode(-(index + 1), node);
		}
	}
}
