package cppclassanalyzer.plugin.typemgr;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.util.List;

import javax.help.UnsupportedOperationException;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoArchiveNode;
import cppclassanalyzer.plugin.typemgr.node.TypeInfoRootNode;

import cppclassanalyzer.data.manager.ProjectClassTypeInfoManager;
import docking.dnd.GenericDataFlavor;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;

public final class TypeInfoDragNDropHandler implements GTreeDragNDropHandler {

	private static final DataFlavor FLAVOR = new GenericDataFlavor(
		DataFlavor.javaJVMLocalObjectMimeType +
		"; class=java.util.List", "Local list of Drag/Drop TypeInfoTreeNode objects");

	@Override
	public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> transferNodes) {
		boolean acceptable = transferNodes.stream()
			.allMatch(TypeInfoArchiveNode.class::isInstance);
		return acceptable ? new DataFlavor[] { FLAVOR } : new DataFlavor[0];
	}

	@Override
	public Object getTransferData(List<GTreeNode> transferNodes, DataFlavor flavor)
			throws UnsupportedFlavorException {
		if (flavor != FLAVOR) {
			throw new UnsupportedFlavorException(flavor);
		}
		return transferNodes;
	}

	@Override
	public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction) {
		return true;
	}

	@Override
	public int getSupportedDragActions() {
		return DnDConstants.ACTION_COPY_OR_MOVE;
	}

	@Override
	public boolean isDropSiteOk(GTreeNode node, DataFlavor[] flavors, int dropAction) {
		if (node == null || !((node instanceof TypeInfoRootNode))) {
			return false;
		}
		if (flavors.length != 1 || flavors[0] != FLAVOR) {
			return false;
		}
		TypeInfoRootNode root = (TypeInfoRootNode) node;
		return root.getTypeManager() instanceof ProjectClassTypeInfoManager;
	}

	@Override
	public void drop(GTreeNode destUserData, Transferable transferable, int dropAction) {
		throw new UnsupportedOperationException("Old API call?");
	}

}
