package cppclassanalyzer.plugin.typemgr.node;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import docking.widgets.tree.GTreeNode;

public final class ProjectArchiveTypeInfoNode extends AbstractManagerNode {

	public ProjectArchiveTypeInfoNode(ProjectClassTypeInfoManager manager) {
		super(manager);
	}

	public void addNode(LibraryClassTypeInfoManager libManager) {
		addNode(new TypeInfoLibraryNode(libManager));
	}

	@Override
	public void addNode(ClassTypeInfoDB type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public TypeInfoNode getNode(ClassTypeInfoDB type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof TypeInfoRootNode) {
			TypeInfoRootNode other = (TypeInfoRootNode) node;
			if (other.getTypeManager() instanceof ProgramClassTypeInfoManager) {
				return 1;
			}
			return -1;
		}
		return super.compareTo(node);
	}

	@Override
	public ProjectClassTypeInfoManager getTypeManager() {
		return (ProjectClassTypeInfoManager) super.getTypeManager();
	}
}
