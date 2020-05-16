package ghidra.app.plugin.prototype.typemgr;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.database.data.rtti.manager.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.util.exception.AssertException;

import docking.widgets.tree.GTreeNode;
import resources.ResourceManager;

public class TypeInfoRootNode extends GTreeNode {

	private final ClassTypeInfoManager manager;

	public TypeInfoRootNode(ClassTypeInfoManager manager) {
		this.manager = manager;
	}

	@Override
	public String getName() {
		return manager.getName();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		IconSet icon = IconSet.getIconSet(manager);
		return expanded ? icon.opened : icon.closed;
	}

	@Override
	public String getToolTip() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isLeaf() {
		return manager.getTypeCount() == 0;
	}

	public boolean isProgramNode() {
		return manager instanceof ProgramClassTypeInfoManager;
	}

	public ClassTypeInfoManager getManager() {
		return manager;
	}

	public void addNode(ClassTypeInfoDB type) {
		String[] paths = type.getSymbolPath().asArray();
		GTreeNode node = this;
		for (String path : paths) {
			GTreeNode currentNode = node.getChild(path);
			if (currentNode == null) {
				if (path == paths[paths.length - 1]) {
					currentNode = new TypeInfoNode(type);
				} else {
					currentNode = new NamespacePathNode(path);
				}
				node.addNode(currentNode);
			}
			node = currentNode;
		}
		if (node instanceof NamespacePathNode) {
			GTreeNode parent = node.getParent();
			parent.removeNode(node);
			GTreeNode currentNode = new TypeInfoNode(type, (NamespacePathNode) node);
			currentNode.addNode(node);
			parent.addNode(currentNode);
		}
		children().sort(null);
	}

	public void removeNode(ClassTypeInfo type) {
		GTreeNode node = getNode(type);
		if (node != null) {
			removeNode(node);
		}
	}

	TypeInfoNode getNode(ClassTypeInfo type) {
		GTreeNode node = this;
		for (String path : type.getSymbolPath().asArray()) {
			GTreeNode currentNode = node.getChild(path);
			if (currentNode == null) {
				currentNode = node.getChild(node.getName());
				if (currentNode != null) {
					currentNode = currentNode.getChild(path);
				}
				if (currentNode == null) {
					throw new AssertException("Node for "+type.getName()+" not found");
				}
			}
			node = currentNode;
		}
		if (node instanceof TypeInfoNode) {
			return (TypeInfoNode) node;
		}
		node = node.getChild(type.getName());
		if (node instanceof TypeInfoNode) {
			return (TypeInfoNode) node;
		}
		throw new AssertException("Node for "+type.getName()+" is not a TypeInfoNode");
	}

	private static class IconSet {

		private static final IconSet FILE_SET =
			new IconSet("images/openBookGreen.png", "images/closedBookGreen.png");
		private static final IconSet PROGRAM_SET =
			new IconSet("images/openBookRed.png", "images/closedBookRed.png");
		//private static final IconSet PROJECT_SET =
		//	new IconSet("images/openBookBlue.png", "images/closedBookBlue.png");

		private final Icon opened;
		private final Icon closed;

		private IconSet(String opened, String closed) {
			this.opened = ResourceManager.loadImage(opened);
			this.closed = ResourceManager.loadImage(closed);
		}

		static IconSet getIconSet(ClassTypeInfoManager manager) {
			if (manager instanceof ProgramClassTypeInfoManager) {
				return PROGRAM_SET;
			} else if (manager instanceof ArchiveClassTypeInfoManager) {
				return FILE_SET;
			} else {
				return null;
			}
		}
	}

}