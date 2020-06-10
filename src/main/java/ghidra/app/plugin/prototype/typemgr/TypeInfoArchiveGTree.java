package ghidra.app.plugin.prototype.typemgr;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import ghidra.app.plugin.prototype.TypeInfoManagerListener;
import ghidra.app.plugin.prototype.typemgr.node.ProjectArchiveTypeInfoNode;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoArchiveNode;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoNode;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoRootNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;
import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;

@SuppressWarnings("serial")
public final class TypeInfoArchiveGTree extends GTree implements TypeInfoManagerListener {

	private final ClassTypeInfoManagerPlugin plugin;
	private final TypeInfoDragNDropHandler dropHandler;

	public TypeInfoArchiveGTree(ClassTypeInfoManagerPlugin plugin) {
		super(new TypeInfoArchiveGTreeRootNode());
		this.plugin = plugin;
		this.dropHandler = new TypeInfoDragNDropHandler();
		plugin.addTypeInfoManagerChangeListener(this);
	}

	private TypeInfoArchiveGTreeRootNode getRoot() {
		return (TypeInfoArchiveGTreeRootNode) getModelRoot();
	}

	@Override
	public GTreeDragNDropHandler getDragNDropHandler() {
		return dropHandler;
	}

	@Override
	public void setDragNDropHandler(GTreeDragNDropHandler dummy) {
	}

	@Override
	public void dispose() {
		super.dispose();
		plugin.removeTypeInfoManagerChangeListener(this);
	}

	@Override
	public void managerOpened(ClassTypeInfoManager manager) {
		if (manager instanceof LibraryClassTypeInfoManager) {
			LibraryClassTypeInfoManager libMan = (LibraryClassTypeInfoManager) manager;
			ProjectArchiveTypeInfoNode node =
				(ProjectArchiveTypeInfoNode) getRoot().getNode(libMan.getProjectManager());
			node.addNode(libMan);
		} else {
			getRoot().addNode(manager);
		}
		repaint();
	}

	@Override
	public void managerClosed(ClassTypeInfoManager manager) {
		getRoot().removeNode(manager);
		repaint();
	}

	private TypeInfoArchiveNode getManagerNode(ClassTypeInfoDB type) {
		return getRoot().getNode(type.getManager());
	}

	@Override
	public void typeAdded(ClassTypeInfoDB type) {
		getManagerNode(type).addNode(type);
	}

	@Override
	public void typeRemoved(ClassTypeInfoDB type) {
		GTreeNode node = getNode(type);
		if (node != null && node.getName().equals(type.getName())) {
			GTreeNode root = (GTreeNode) getManagerNode(type);
			root.removeNode(node);
		}
	}

	@Override
	public void typeUpdated(ClassTypeInfoDB type) {
		TypeInfoNode node = getNode(type);
		node.typeUpdated(type);
	}

	TypeInfoNode getNode(ClassTypeInfoDB type) {
		return getManagerNode(type).getNode(type);
	}

	public List<GTreeNode> getSelectedNodes() {
		TreePath[] selectionPaths = getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length == 0) {
			return Collections.emptyList();
		}
		return Arrays.stream(selectionPaths)
			.map(TreePath::getLastPathComponent)
			.filter(GTreeNode.class::isInstance)
			.map(GTreeNode.class::cast)
			.collect(Collectors.toList());
	}

	private static class TypeInfoArchiveGTreeRootNode extends GTreeNode {

		@Override
		public String getName() {
			return "TypeInfo Archives";
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return DataTypeUtils.getRootIcon(expanded);
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		void addNode(ClassTypeInfoManager manager) {
			if (manager instanceof ProjectClassTypeInfoManager) {
				addNode(new ProjectArchiveTypeInfoNode((ProjectClassTypeInfoManager) manager));
			} else {
				addNode(new TypeInfoRootNode(manager));
			}
			children().sort(null);
			doFireNodeStructureChanged();
		}

		void removeNode(ClassTypeInfoManager manager) {
			GTreeNode node = getNode(manager).getNode();
			removeNode(node);
			node.dispose();
			doFireNodeStructureChanged();
		}

		TypeInfoArchiveNode getNode(ClassTypeInfoManager manager) {
			if (manager instanceof LibraryClassTypeInfoManager) {
				LibraryClassTypeInfoManager libMan = (LibraryClassTypeInfoManager) manager;
				ProjectArchiveTypeInfoNode node =
					(ProjectArchiveTypeInfoNode) getNode(libMan.getProjectManager());
				return (TypeInfoArchiveNode) node.getChild(manager.getName());
			}
			return (TypeInfoArchiveNode) getChild(manager.getName());
		}

	}

}