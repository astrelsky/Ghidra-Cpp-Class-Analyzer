package ghidra.app.plugin.prototype.typemgr;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.tree.TreePath;

import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;
import ghidra.app.plugin.prototype.typemgr.action.TypeInfoArchiveHandler;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoNode;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

import resources.ResourceManager;

public class TypeInfoTreeProvider extends ComponentProviderAdapter {

	private static final String NAME = "ClassTypeInfo Tree";
	private static Icon ICON = ResourceManager.loadImage("images/c++-icon.png");

	private final ClassTypeInfoManagerPlugin plugin;
	private final TreeMouseListener mouseListener = new TreeMouseListener();
	private JPanel mainPanel;
	private TypeInfoArchiveGTree tree;

	public TypeInfoTreeProvider(PluginTool tool, ClassTypeInfoManagerPlugin plugin) {
		super(tool, NAME, plugin.getName());
		this.plugin = plugin;
		setIcon(ICON);
		buildProvider();
		addToToolbar();
		plugin.getTool().addComponentProvider(this, false);
		createActions();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public TypeInfoArchiveGTree getTree() {
		return tree;
	}

	private void buildProvider() {
		mainPanel = new JPanel(new BorderLayout());

		tree = new TypeInfoArchiveGTree(plugin);
		mainPanel.add(tree, BorderLayout.CENTER);
		tree.addMouseListener(mouseListener);

		tree.setRootVisible(true);
	}

	private void createActions() {
		// TODO things like graph n stuff
		TypeInfoArchiveHandler handler = new TypeInfoArchiveHandler(plugin);
		addLocalAction(handler.getOpenAction());
		addLocalAction(handler.getCreateAction());
		addLocalAction(handler.getCloseAction());
		addLocalAction(handler.getOpenForEditAction());
		addLocalAction(handler.getSaveAction());
		addLocalAction(handler.getCreateProjectArchiveAction());
		addLocalAction(handler.getOpenProjectArchiveAction());
		addLocalAction(handler.getCopyArchiveAction());
		addLocalAction(handler.getPasteArchiveAction());
	}

	public void dispose() {
		tree.dispose();
		mainPanel.removeAll();
	}

	private void goToTypeInfo() {

		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null || paths.length != 1) {
			return;
		}

		Object object = paths[0].getLastPathComponent();
		if (!(object instanceof TypeInfoNode)) {
			return;
		}
		plugin.goTo((TypeInfoNode) object);
	}

	private class TreeMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {
			if (e.getClickCount() == 2 && !e.isConsumed()) {
				e.consume();
				goToTypeInfo();
			}
		}
	}

}