package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;
import ghidra.util.datastruct.LongArrayList;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;

import static ghidra.program.model.data.DataTypeConflictHandler.*;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.getCxxAbiCategoryPath;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class VmiClassTypeInfoModel extends AbstractClassTypeInfoModel {

	public static final String STRUCTURE_NAME = "__vmi_class_type_info";
	private static final String DESCRIPTION =
		"Model for Virtual Multiple Inheritance Class Type Info";

	public static final String ID_STRING = "N10__cxxabiv121__vmi_class_type_infoE";

	private static final String FLAGS_NAME = "__flags";
	private static final String BASE_COUNT_NAME = "__base_count";
	private static final String ARRAY_NAME = "__base_info";

	public static final String DIAMOND_MASK_NAME = "__diamond_shaped_mask";
	public static final String NON_DIAMOND_MASK_NAME = "__non_diamond_repeat_mask";

	private static final int FLAGS_ORDINAL = 1;
	private static final int BASE_COUNT_ORDINAL = 2;

	protected static final CategoryPath SUB_PATH =
		new CategoryPath(getCxxAbiCategoryPath(), STRUCTURE_NAME);

	public static enum Flags {
		NON_DIAMOND,
		DIAMOND,
		NON_PUBLIC,
		PUBLIC,
		UNKNOWN
	}

	private final BaseClassTypeInfoHelper helper;
	private BaseClassTypeInfoModel[] bases;
	private Flags flags;

	public static VmiClassTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new VmiClassTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(
				TypeInfoUtils.getErrorMessage(program, address, ID_STRING));
	}

	/**
	 * Constructs a new VmiClassTypeInfoModel
	 * NOTE: This is only for pre-validated data
	 * @param program the program
	 * @param address the typeinfo address
	 */
	public VmiClassTypeInfoModel(Program program, Address address) {
		super(program, address);
		this.helper = new BaseClassTypeInfoHelper(program, address);
		this.bases = helper.getBases();
		this.flags = getFlags(getBuffer());
	}

	/**
	 * Gets the {@value #STRUCTURE_NAME} datatype
	 */
	@Override
	public Structure getDataType() {
		return getDataType(program.getDataTypeManager());
	}

	public Flags getFlags() {
		return flags;
	}

	/**
	 * Gets the {@value #STRUCTURE_NAME} datatype
	 * @param dtm the DataTypeManager
	 * @return the {@value #STRUCTURE_NAME} datatype
	 */
	public static Structure getDataType(DataTypeManager dtm) {
		DataType existingDt = dtm.getDataType(GnuUtils.getCxxAbiCategoryPath(), STRUCTURE_NAME);
		StructureDataType struct =
			new StructureDataType(GnuUtils.getCxxAbiCategoryPath(), STRUCTURE_NAME, 0, dtm);
		struct.add(ClassTypeInfoModel.getDataType(dtm),
			AbstractTypeInfoModel.SUPER + ClassTypeInfoModel.STRUCTURE_NAME, null);
		struct.add(getFlags(dtm, SUB_PATH), FLAGS_NAME, null);
		struct.add(IntegerDataType.dataType.clone(dtm), BASE_COUNT_NAME, null);
		DataType bdt = BaseClassTypeInfoModel.getDataType(dtm);
		ArrayDataType adt = new ArrayDataType(bdt, 0, bdt.getLength());
		struct.add(adt, ARRAY_NAME, null);
		struct.setDescription(DESCRIPTION);
		if (existingDt != null && existingDt.isEquivalent(struct)) {
			return (Structure) existingDt;
		}
		return (Structure) dtm.resolve(struct, REPLACE_HANDLER);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	@Override
	public boolean hasParent() {
		return true;
	}

    private List<ClassTypeInfo> getParents() {
        List<ClassTypeInfo> parents = new ArrayList<>();
        for (BaseClassTypeInfoModel base : bases) {
            if (!base.isVirtual()) {
                parents.add(base.getClassModel());
            }
        }
        try {
            parents.addAll(getInheritableVirtualParents());
        } catch (NullPointerException e) {
            throw e;
        }
        return parents;
    }

	@Override
	public ClassTypeInfo[] getParentModels() {
		return getParents().toArray(ClassTypeInfo[]::new);
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		Set<ClassTypeInfo> result = new LinkedHashSet<>();
		for (BaseClassTypeInfoModel base : bases) {
			ClassTypeInfo parent = base.getClassModel();
			if (base.isVirtual()) {
				result.add(parent);
			}
			result.addAll(parent.getVirtualParents());
		}
		return result;
	}

	private Set<ClassTypeInfo> getInheritableVirtualParents() {
		Set<ClassTypeInfo> result = new LinkedHashSet<>();
		for (BaseClassTypeInfoModel base : bases) {
			ClassTypeInfo parent = base.getClassModel();
			if (base.isVirtual()) {
				result.add(parent);
			}
			result.addAll(parent.getVirtualParents());
		}
		return result;
	}

	/**
	 * Gets this {@value #STRUCTURE_NAME}'s {@value BaseClassTypeInfoModel#STRUCTURE_NAME} array
	 * @return the BaseClassTypeInfo[] representation of
	 * the {@value BaseClassTypeInfoModel#STRUCTURE_NAME} array.
	 */
	public BaseClassTypeInfoModel[] getBases() {
		return bases;
	}

	public static BaseClassTypeInfoModel[] getBases(Program program, Address address) {
		return new BaseClassTypeInfoHelper(program, address).getBases();
	}

	/**
	 * Gets a list of the offsets of each derived class within this class
	 * @return a list containing the offsets of each derived class within this class
	 */
	public List<Long> getOffsets() {
		LongArrayList result = new LongArrayList();
		for (BaseClassTypeInfoModel base : bases) {
			if(!base.isVirtual()) {
				result.add((long) base.getOffset());
			}
		}
		if (Vtable.isValid(findVtable())) {
			List<Long> offsets = new ArrayList<>(getVtable().getPrefixes().get(0).getOffsets());
			if (offsets.size() > 0) {
				offsets.sort(null);
				offsets.remove(0);
				result.addAll(offsets);
			}
		}
		return result;
	}

	private static DataType getFlags(DataTypeManager dtm, CategoryPath path) {
		DataType integer = IntegerDataType.dataType.clone(dtm);
		EnumDataType flags =
			new EnumDataType(path, "__flags_masks", integer.getLength(), dtm);

		// Populate the flags mask
		flags.add(NON_DIAMOND_MASK_NAME, 1);
		flags.add(DIAMOND_MASK_NAME, 2);
		flags.add("non_public_base_mask", 4);
		flags.add("public_base_mask", 8);
		flags.add("__flags_unknown_mask", 16);
		return dtm.resolve(flags, KEEP_HANDLER);
	}

	/**
	 * Gets the value of this datatypes's __flags_mask
	 * @param buf the buffer containing the {@value #STRUCTURE_NAME}
	 * @return the value of this datatypes's __flags_mask
	 */
	public Flags getFlags(MemBuffer buf) {
		try {
			DataTypeComponent comp = getDataType().getComponent(FLAGS_ORDINAL);
			int offset = comp.getOffset();
			int length = comp.getLength();
			switch(buf.getVarLengthInt(offset, length)) {
				case 1:
					return Flags.NON_DIAMOND;
				case 2:
					return Flags.DIAMOND;
				case 4:
					return Flags.NON_PUBLIC;
				case 8:
					return Flags.PUBLIC;
				case 16:
				default:
					return Flags.UNKNOWN;
			}
		} catch (MemoryAccessException e) {
			return Flags.UNKNOWN;
		}
	}

	/**
	 * Gets the DataType representation of the __base_class_type_info array
	 * @return the DataType representation of the __base_class_type_info array
	 */
	public DataType getBaseArrayDataType() {
		DataType base = BaseClassTypeInfoModel.getDataType(program.getDataTypeManager());
		return new ArrayDataType(base, helper.count, base.getLength(), program.getDataTypeManager());
	}

	public static DataType getBaseArrayDataType(Data data) {
		DataType dt = data.getDataType();
		DataTypeManager dtm = dt.getDataTypeManager();
		if (!dt.equals(getDataType(dtm))) {
			return null;
		}
		try {
			int baseCount = data.getComponent(BASE_COUNT_ORDINAL).getInt(0);
			dt = BaseClassTypeInfoModel.getDataType(dtm);
			return new ArrayDataType(dt, baseCount, dt.getLength(), dtm);
		} catch (MemoryAccessException e) {
			// shouldn't occur
			throw new RuntimeException(e);
		}
	}

	private static class BaseClassTypeInfoHelper {

		private final Program program;
		private final Address address;
		private final int count;

		BaseClassTypeInfoHelper(Program program, Address address) {
			this.program = program;
			this.address = getArrayAddress(address);
			this.count = getBaseCount(address);
		}

		private Address getArrayAddress(Address addr) {
			Structure dt = getDataType(program.getDataTypeManager());
			DataTypeComponent arrayComponent = dt.getDefinedComponents()[dt.getNumDefinedComponents()-1];
			return addr.add(arrayComponent.getOffset());
		}

		private int getBaseCount(Address addr) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataTypeComponent comp = getDataType(dtm).getComponent(BASE_COUNT_ORDINAL);
			try {
				MemBuffer buf = new MemoryBufferImpl(program.getMemory(), addr);
				return buf.getVarLengthInt(comp.getOffset(), comp.getLength());
			} catch (MemoryAccessException e) {
				Msg.error(VmiClassTypeInfoModel.class, e);
				return 0;
			}
		}

		private BaseClassTypeInfoModel[] getBases() {
			BaseClassTypeInfoModel[] bases = new BaseClassTypeInfoModel[count];
			Address currentAddress = address;
			int size =
				BaseClassTypeInfoModel.getDataType(program.getDataTypeManager()).getLength();
			for (int i = 0; i < count; i++) {
				bases[i] = new BaseClassTypeInfoModel(program, currentAddress);
				currentAddress = currentAddress.add(size);
			}
			return bases;
		}
	}
}
