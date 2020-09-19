package cppclassanalyzer.plugin.typemgr.node;

import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.WritableRaster;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import ghidra.program.model.address.Address;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.plugin.typemgr.icon.*;
import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import generic.util.image.ImageUtils;
import resources.ResourceManager;
import resources.icons.ImageIconWrapper;

public final class TypeInfoNode extends GTreeLazyNode implements TypeInfoTreeNode {

	private final boolean isVirtual;
	private ClassTypeInfoDB type;
	private ModifierType modifier;
	private List<GTreeNode> nested = Collections.synchronizedList(new ArrayList<>());

	TypeInfoNode(ClassTypeInfoDB type) {
		this(type, (ModifierType) null);
	}

	private TypeInfoNode(ClassTypeInfoDB type, ModifierType modifier) {
		this.isVirtual = modifier == ModifierType.VIRTUAL;
		this.type = type;

		// will determine if type is also abstract
		this.modifier = getModifier();
	}

	// conversion constructor
	TypeInfoNode(ClassTypeInfoDB type, NamespacePathNode existing) {
		this.isVirtual = false;
		this.type = type;
		this.modifier = getModifier();
		List<GTreeNode> children = new ArrayList<>(existing.getChildren());
		children.forEach(existing::removeNode);
		GTreeNode parent = existing.getParent();
		parent.removeNode(existing);
		parent.addNode(this);
		nested.addAll(children);
		for (GTreeNode node : nested) {
			if (node instanceof TypeInfoNode) {
				((TypeInfoNode) node).modifier = ModifierType.NESTED;
			}
		}
	}

	private ModifierType getModifier() {
		if (modifier == ModifierType.NESTED) {
			return modifier;
		}
		if (type.isAbstract()) {
			return isVirtual ? ModifierType.VIRTUAL_ABSTRACT : ModifierType.ABSTRACT;
		}
		return isVirtual ? ModifierType.VIRTUAL : ModifierType.NORMAL;
	}

	@Override
	public GTreeNode clone() {
		return this;
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof NamespacePathNode) {
			return 1;
		}
		return super.compareTo(node);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o instanceof TypeInfoNode) {
			return type.equals(((TypeInfoNode) o).type);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return type.hashCode();
	}

	@Override
	public String toString() {
		return type.toString();
	}

	@Override
	public String getName() {
		return type.getName();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return modifier.getIcon();
	}

	@Override
	public String getToolTip() {
		return modifier.getModifier() + " " + type.getName();
	}

	@Override
	public boolean isLeaf() {
		return !type.hasParent();
	}

	@Override
	public void addNode(GTreeNode node) {
		if (node instanceof TypeInfoNode) {
			((TypeInfoNode) node).modifier = ModifierType.NESTED;
		}
		nested.add(node);
	}

	public ClassTypeInfoDB getType() {
		return type;
	}

	public void typeUpdated(ClassTypeInfoDB type) {
		this.type = type;
		modifier = getModifier();
	}

	public Address getAddress() {
		if (type instanceof ArchivedClassTypeInfo) {
			return null;
		}
		return type.getAddress();
	}

	@Override
	public TypeInfoTreeNodeManager getManager() {
		return type.getManager().getTreeNodeManager();
	}

	private static enum ModifierType {
		NORMAL,
		ABSTRACT,
		VIRTUAL,
		VIRTUAL_ABSTRACT,
		NESTED;

		private static String[] MODIFIERS = new String[]{
			"class",
			"abstract class",
			"virtual base class",
			"virtual abstract base class",
			"nested class"
		};

		private static final ImageIcon CLASS_ICON = ResourceManager.loadImage("images/class.png");

		private static Icon[] ICONS = new Icon[]{
			CLASS_ICON,
			createIcon(ABSTRACT),
			createIcon(VIRTUAL),
			createIcon(VIRTUAL_ABSTRACT),
			createIcon(NESTED)
		};

		private static Icon createIcon(ModifierType type) {
			BufferedImage image = ImageUtils.getBufferedImage(CLASS_ICON.getImage());
			ColorModel model = null;
			switch (type) {
				case ABSTRACT:
					model = new RedGreenSwappedColorModel(image.getColorModel());
					break;
				case NORMAL:
					break;
				case VIRTUAL:
					model = new BlueGreenSwappedColorModel(image.getColorModel());
					break;
				case VIRTUAL_ABSTRACT:
					model = new PurpleSwappedColorModel(image.getColorModel());
					break;
				case NESTED:
					model = new YellowSwappedColorModel(image.getColorModel());
					break;
				default:
					break;
			}
			WritableRaster raster = image.getRaster();
			Hashtable<String, Object> properties = getProperties(image);
			boolean preMultiplied = image.isAlphaPremultiplied();
			image = new BufferedImage(model, raster, preMultiplied, properties);
			return new ImageIconWrapper(image, type.name());
		}

		private static Hashtable<String, Object> getProperties(BufferedImage image) {
			String[] names = image.getPropertyNames();
			if (names == null) {
				return null;
			}
			Hashtable<String, Object> table = new Hashtable<>(names.length);
			for (String name : names) {
				table.put(name, image.getProperty(name));
			}
			return table;
		}

		Icon getIcon() {
			return ICONS[ordinal()];
		}

		String getModifier() {
			return MODIFIERS[ordinal()];
		}
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		List<GTreeNode> parents;
		Set<GTreeNode> vParents;
		synchronized (type.getManager()) {
			parents = Arrays.stream(type.getParentModels())
				.map(TypeInfoNode::new)
				.collect(Collectors.toList());
			vParents = type.getVirtualParents()
				.stream()
				.map(ClassTypeInfoDB.class::cast)
				.map(p -> new TypeInfoNode(p, ModifierType.VIRTUAL))
				.collect(Collectors.toCollection(LinkedHashSet::new));
		}
		vParents.addAll(parents);
		List<GTreeNode> result = new ArrayList<>(vParents);
		result.addAll(nested);
		result.sort(null);
		return result;
	}
}
