package ghidra.app.plugin.prototype.typemgr;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;

import ghidra.program.database.data.rtti.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.ProgramClassTypeInfoManager;
import ghidra.program.database.data.rtti.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.model.address.Address;
import ghidra.util.exception.AssertException;

import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import resources.ResourceManager;

public class TypeInfoNode extends GTreeLazyNode implements AddressableTreeNode {

	private final Object key;
	private final NamespacePathNode nested;
	private final boolean isVirtual;
	private ClassTypeInfoDB type;
	private ModifierType modifier;

	TypeInfoNode(ClassTypeInfoDB type) {
		this(type, null);
	}

	TypeInfoNode(ClassTypeInfoDB type, NamespacePathNode nested) {
		this(type, nested, false);
	}

	private TypeInfoNode(ClassTypeInfoDB type, NamespacePathNode nested, boolean isVirtual) {
		this.key = getKey(type);
		this.nested = nested;
		this.isVirtual = isVirtual;
		this.type = type;
		this.modifier = getModifier();
		if (nested != null) {
			nested.setToolTip("Nested Classes");
		}
	}

	private static Object getKey(ClassTypeInfoDB type) {
		if (type instanceof AbstractClassTypeInfoDB) {
			// these keys can change but the address will not
			return type.getAddress();
		}
		return Long.valueOf(type.getKey());
	}

	private ModifierType getModifier() {
		if (type.isAbstract()) {
			return isVirtual ? ModifierType.VIRTUAL_ABSTRACT : ModifierType.ABSTRACT;
		}
		return isVirtual ? ModifierType.VIRTUAL : ModifierType.NORMAL;
	}

	private void refresh() {
		ClassTypeInfoManager manager = type.getManager();
		if (key instanceof Address) {
			type = ((ProgramClassTypeInfoManager) manager).getType((Address) key);
		} else if (key instanceof Long) {
			type = ((ArchiveClassTypeInfoManager) manager).getClass((Long) key);
		} else {
			// impossible
			throw new AssertException("Unexpected class for TypeInfoNode key");
		}
	}

	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		return super.clone();
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
			.map(p -> new TypeInfoNode(p, null, true))
			.collect(Collectors.toCollection(LinkedHashSet::new));
		vParents.addAll(parents);
		List<GTreeNode> result = new ArrayList<>(vParents);
		if (nested != null) {
			result.add(nested);
		}
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
	public boolean hasAddress() {
		return type.getManager() instanceof ProgramClassTypeInfoManager;
	}

	@Override
	public Address getAddress() {
		return type.getAddress();
	}

	public ClassTypeInfoDB getType() {
		return type;
	}

	void typeUpdated() {
		refresh();
		modifier = getModifier();
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

		private static Icon[] ICONS = new Icon[]{
			ResourceManager.loadImage("images/class.png"),
			ResourceManager.loadImage("images/abstract_class.png"),
			ResourceManager.loadImage("images/virtual_class.png"),
			ResourceManager.loadImage("images/virtual_abstract_class.png")
		};

		Icon getIcon() {
			return ICONS[ordinal()];
		}

		String getModifier() {
			return MODIFIERS[ordinal()];
		}
	};

}