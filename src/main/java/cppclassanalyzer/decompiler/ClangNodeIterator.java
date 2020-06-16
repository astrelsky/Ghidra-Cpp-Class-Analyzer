package cppclassanalyzer.decompiler;

import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;

import util.CollectionUtils;

public class ClangNodeIterator implements Iterator<ClangNode>, Iterable<ClangNode> {

	private final ClangTokenGroup group;
	private int index;

	public ClangNodeIterator(ClangTokenGroup group) {
		this.group = group;
		this.index = 0;
	}


	@Override
	public Iterator<ClangNode> iterator() {
		return this;
	}


	@Override
	public boolean hasNext() {
		return index < group.numChildren();
	}


	@Override
	public ClangNode next() {
		return group.Child(index++);
	}

	public Stream<ClangNode> stream() {
		return CollectionUtils.asStream(this);
	}

	public void reset() {
		index = 0;
	}

	public List<ClangNode> toList() {
		ClangNode[] nodes = new ClangNode[group.numChildren()];
		for (int i = 0; i < nodes.length; i++) {
			nodes[i] = group.Child(i);
		}
		return List.of(nodes);
	}
}