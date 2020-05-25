package ghidra.app.plugin.prototype.typemgr;

import javax.swing.Icon;

import ghidra.app.plugin.prototype.TypeInfoManagerListener;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoNode;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoRootNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

@SuppressWarnings("serial")
public class TypeInfoArchiveGTree extends GTree implements TypeInfoManagerListener {

	private final ClassTypeInfoManagerPlugin plugin;

	public TypeInfoArchiveGTree(ClassTypeInfoManagerPlugin plugin) {
		super(new TypeInfoArchiveGTreeRootNode());
		this.plugin = plugin;
		plugin.addTypeInfoManagerChangeListener(this);
	}

	private TypeInfoArchiveGTreeRootNode getRoot() {
		return (TypeInfoArchiveGTreeRootNode) getModelRoot();
	}

	@Override
	public void dispose() {
		super.dispose();
		plugin.removeTypeInfoManagerChangeListener(this);
	}

	@Override
	public void managerOpened(ClassTypeInfoManager manager) {
		getRoot().addNode(manager);
	}

	@Override
	public void managerClosed(ClassTypeInfoManager manager) {
		getRoot().removeNode(manager);
	}

	private TypeInfoRootNode getManagerNode(ClassTypeInfoDB type) {
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
			GTreeNode root = getManagerNode(type);
			root.removeNode(node);
		}
	}

	@Override
	public void typeUpdated(ClassTypeInfoDB type) {
		TypeInfoNode node = getNode(type);
		if (node != null && node.getType().equals(type)) {
			node.typeUpdated(type);
		}
	}

	TypeInfoNode getNode(ClassTypeInfoDB type) {
		return getManagerNode(type).getNode(type);
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
			addNode(new TypeInfoRootNode(manager));
		}

		void removeNode(ClassTypeInfoManager manager) {
			removeNode(getNode(manager));
		}

		TypeInfoRootNode getNode(ClassTypeInfoManager manager) {
			return (TypeInfoRootNode) getChild(manager.getName());
		}

	}

}