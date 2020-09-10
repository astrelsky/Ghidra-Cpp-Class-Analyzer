package cppclassanalyzer.plugin.typemgr.node;

import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.WritableRaster;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import cppclassanalyzer.plugin.typemgr.icon.BlueGreenSwappedColorModel;
import cppclassanalyzer.plugin.typemgr.icon.PurpleSwappedColorModel;
import cppclassanalyzer.plugin.typemgr.icon.RedGreenSwappedColorModel;
import ghidra.program.model.address.Address;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;

import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import generic.util.image.ImageUtils;
import resources.ResourceManager;
import resources.icons.ImageIconWrapper;

import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

public final class TypeInfoNode extends GTreeLazyNode implements TypeInfoTreeNode {

	private final boolean isVirtual;
	private final TypeInfoTreeNodeRecord record;
	private NamespacePathNode nested;
	private ClassTypeInfoDB type;
	private ModifierType modifier;

	private TypeInfoNode(ClassTypeInfoDB type) {
		this(type, false);
	}

	private TypeInfoNode(ClassTypeInfoDB type, boolean isVirtual) {
		this.isVirtual = isVirtual;
		this.type = type;
		this.modifier = getModifier();
		this.record = null;
		this.nested = null;
	}

	TypeInfoNode(ClassTypeInfoDB type, TypeInfoTreeNodeRecord record) {
		this.isVirtual = false;
		this.record = record;
		this.type = type;
		this.modifier = getModifier();
		long[] kids = record.getLongArray(CHILDREN_KEYS);
		if (kids.length > 0) {
			this.nested = new NamespacePathNode(getManager(), record);
		}
	}

	TypeInfoNode(ClassTypeInfoDB type, NamespacePathNode nested) {
		this.isVirtual = false;
		this.nested = nested;
		this.record = nested.getRecord();
		this.type = type;
		this.modifier = getModifier();
		record.setByteValue(TYPE_ID, TypeInfoTreeNodeRecord.TYPEINFO_NODE);
		getManager().updateRecord(record);
	}

	private ModifierType getModifier() {
		if (type.isAbstract()) {
			return isVirtual ? ModifierType.VIRTUAL_ABSTRACT : ModifierType.ABSTRACT;
		}
		return isVirtual ? ModifierType.VIRTUAL : ModifierType.NORMAL;
	}

	@Override
	public void addNode(GTreeNode node) {
		if (nested == null) {
			nested = new NamespacePathNode(getManager(), record);
		}
		nested.addNode(node);
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
	protected List<GTreeNode> generateChildren() {
		List<GTreeNode> parents = Arrays.stream(type.getParentModels())
			.map(TypeInfoNode::new)
			.collect(Collectors.toList());
		Set<GTreeNode> vParents = type.getVirtualParents()
			.stream()
			.map(ClassTypeInfoDB.class::cast)
			.map(p -> new TypeInfoNode(p, true))
			.collect(Collectors.toCollection(LinkedHashSet::new));
		vParents.addAll(parents);
		List<GTreeNode> result = new ArrayList<>(vParents);
		if (nested != null) {
			result.add(nested);
		}
		result.sort(null);
		return result;
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

	public ClassTypeInfoDB getType() {
		return type;
	}

	public void typeUpdated(ClassTypeInfoDB type) {
		if (getTypeKey() != type.getKey()) {
			record.setLongValue(TYPE_KEY, type.getKey());
			getManager().updateRecord(record);
		}
		this.type = type;
		modifier = getModifier();
	}

	public Address getAddress() {
		if (type instanceof ArchivedClassTypeInfo) {
			return null;
		}
		return type.getAddress();
	}

	private long getTypeKey() {
		return record.getLongValue(TYPE_KEY);
	}

	@Override
	public long getKey() {
		return record.getKey();
	}

	@Override
	public TypeInfoTreeNodeRecord getRecord() {
		return record;
	}

	@Override
	public TypeInfoTreeNodeManager getManager() {
		return type.getManager().getTreeNodeManager();
	}

	private static enum ModifierType {
		NORMAL,
		ABSTRACT,
		VIRTUAL,
		VIRTUAL_ABSTRACT;

		private static String[] MODIFIERS = new String[]{
			"class",
			"abstract class",
			"virtual base class",
			"virtual abstract base class"
		};

		private static final ImageIcon CLASS_ICON = ResourceManager.loadImage("images/class.png");

		private static Icon[] ICONS = new Icon[]{
			CLASS_ICON,
			createIcon(ABSTRACT),
			createIcon(VIRTUAL),
			createIcon(VIRTUAL_ABSTRACT)
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
}
