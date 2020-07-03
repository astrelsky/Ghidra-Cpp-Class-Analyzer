package cppclassanalyzer.decompiler.token;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;

import util.CollectionUtils;

public class ClangTokenGroupIterator implements Iterator<ClangTokenGroup> {

	private final List<ClangTokenGroup> groups;
	private Iterator<ClangTokenGroup> it;
	private ClangTokenGroup group;
	private int index;

	public ClangTokenGroupIterator(ClangTokenGroup group) {
		this.group = group;
		this.groups = ClangNodeUtils.asStream(group)
			.filter(ClangTokenGroupIterator::isTokenGroup)
			.map(ClangTokenGroup.class::cast)
			.collect(Collectors.toList());
		if (groups.isEmpty()) {
			this.it = Collections.emptyIterator();
		} else {
			this.it = new ClangTokenGroupIterator(groups.get(index++));
		}
	}

	private static boolean isTokenGroup(ClangNode node) {
		return node.getClass() == ClangTokenGroup.class;
	}

	@Override
	public boolean hasNext() {
		return group != null || it.hasNext() || index < groups.size();
	}

	@Override
	public ClangTokenGroup next() {
		if (group != null) {
			ClangTokenGroup next = group;
			group = null;
			return next;
		}
		if (!it.hasNext()) {
			it = new ClangTokenGroupIterator(groups.get(index++));
		}
		return it.next();
	}

	public Stream<ClangTokenGroup> stream() {
		return CollectionUtils.asStream(this);
	}

}
