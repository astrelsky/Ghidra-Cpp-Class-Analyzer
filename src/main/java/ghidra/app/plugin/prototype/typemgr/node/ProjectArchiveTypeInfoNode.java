package ghidra.app.plugin.prototype.typemgr.node;

import java.util.List;
import java.util.stream.Collectors;

import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import docking.widgets.tree.GTreeNode;

public final class ProjectArchiveTypeInfoNode extends AbstractManagerNode {

	public ProjectArchiveTypeInfoNode(ProjectClassTypeInfoManager manager) {
		super(manager);
	}

	@Override
	public void addNode(GTreeNode node) {
		super.addNode(node);
		children().sort(null);
	}

	public void addNode(LibraryClassTypeInfoManager libManager) {
		addNode(new TypeInfoLibraryNode(libManager));
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) {
		return ((ProjectClassTypeInfoManager) getTypeManager()).getLibraries()
			.stream()
			.map(TypeInfoLibraryNode::new)
			.collect(Collectors.toList());
	}

	@Override
	public void addNode(ClassTypeInfoDB type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public TypeInfoNode getNode(ClassTypeInfoDB type) {
		throw new UnsupportedOperationException();
	}
}