package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.*;
import java.util.stream.IntStream;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.getCxxAbiCategoryPath;

/**
 * Model for the __vmi_class_type_info class.
 */
public class VmiClassTypeInfoModel extends AbstractClassTypeInfoModel {

    public static final String STRUCTURE_NAME = "__vmi_class_type_info";
    private static final String DESCRIPTION = "Model for Virtual Multiple Inheritance Class Type Info";

    public static final String ID_STRING = "N10__cxxabiv121__vmi_class_type_infoE";

    private static final String FLAGS_NAME = "__flags";
    private static final String BASE_COUNT_NAME = "__base_count";
    private static final String ARRAY_NAME = "__base_info";

    public static final String DIAMOND_MASK_NAME = "__diamond_shaped_mask";
    public static final String NON_DIAMOND_MASK_NAME = "__non_diamond_repeat_mask";

    private static final int FLAGS_ORDINAL = 1;
    private static final int BASE_COUNT_ORDINAL = 2;
    private static final int BASE_ARRAY_ORDINAL = 3;

    protected static final CategoryPath SUB_PATH = new CategoryPath(getCxxAbiCategoryPath(), STRUCTURE_NAME);

    public enum Flags {
        NON_DIAMOND,
        DIAMOND,
        NON_PUBLIC,
        PUBLIC,
        UNKNOWN
    }

    private BaseClassTypeInfoModel[] bases;
    private Flags flags;
    private Map<DataTypeComponent, Integer> dtComps = Collections.emptyMap();

    public VmiClassTypeInfoModel(Program program, Address address) {
        super(program, address);
        if (!typeName.equals(DEFAULT_TYPENAME)) {
            this.bases = getBases();
            this.flags = getFlags(getBuffer());
        }
    }

    @Override
    public Structure getDataType() {
        return getDataType(program.getDataTypeManager());
    }

    public Flags getFlags() {
        return flags;
    }

    /**
     * @see ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel#getDataType(DataTypeManager)
     */
    public static Structure getDataType(DataTypeManager dtm) {
        DataType existingDt = dtm.getDataType(GnuUtils.getCxxAbiCategoryPath(), STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return (Structure) existingDt;
        }
        StructureDataType struct =
            new StructureDataType(GnuUtils.getCxxAbiCategoryPath(), STRUCTURE_NAME, 0, dtm);
        struct.add(ClassTypeInfoModel.getDataType(dtm),
                   AbstractTypeInfoModel.SUPER + ClassTypeInfoModel.STRUCTURE_NAME,
                   null);
        struct.add(getFlags(dtm, VmiClassTypeInfoModel.SUB_PATH), FLAGS_NAME, null);
        struct.add(IntegerDataType.dataType.clone(dtm), BASE_COUNT_NAME, null);
        struct.setFlexibleArrayComponent(
            BaseClassTypeInfoModel.getDataType(dtm), ARRAY_NAME, null);
        struct.setDescription(DESCRIPTION);
        Structure result = (Structure) dtm.resolve(struct, KEEP_HANDLER);
        Structure flexComponent = (Structure) result.getFlexibleArrayComponent().getDataType();
        DataTypeComponent baseFlagsComp = flexComponent.getComponent(
            BaseClassTypeInfoModel.FLAGS_ORDINAL);
        if (baseFlagsComp.getDataType() instanceof Structure) {
            return result;
        }
        return (Structure) dtm.resolve(struct, REPLACE_HANDLER);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    private Address getArrayAddress() {
        DataTypeComponent arrayComponent = getDataType().getFlexibleArrayComponent();
        return address.add(arrayComponent.getOffset());
    }

    @Override
    public boolean hasParent() {
        return true;
    }

    @Override
    public ClassTypeInfo[] getParentModels() throws InvalidDataTypeException {
        validate();
        List<ClassTypeInfo> parents = new ArrayList<>();
        for (int i = 0; i < bases.length; i++) {
            if (!bases[i].isVirtual()) {
                parents.add(bases[i].getClassModel());
            }
        }
        parents.addAll(getVirtualParents());
        return parents.toArray(new ClassTypeInfo[parents.size()]);
    }

    private Set<ClassTypeInfo> getVirtualParents() throws InvalidDataTypeException {
        Set<ClassTypeInfo> result = new LinkedHashSet<>();
        getVirtualBases().values().forEach(result::addAll);
        return result;
    }

    public BaseClassTypeInfoModel getBase(int ordinal) {
        return getBases()[ordinal];
    }

    private int getBaseCount() {
        MemBuffer buf = getBuffer();
        DataTypeComponent comp = getDataType().getComponent(BASE_COUNT_ORDINAL);
        try {
            return buf.getVarLengthInt(comp.getOffset(), comp.getLength());
        } catch (MemoryAccessException e) {
            Msg.error(this, e);
            return 0;
        }
    }

    private BaseClassTypeInfoModel[] getBases() {
        if (bases != null) {
            return bases;
        }
        BaseClassTypeInfoModel base = new BaseClassTypeInfoModel(program, getArrayAddress());
        int baseCount = getBaseCount();
        bases = new BaseClassTypeInfoModel[baseCount];
        for (int i = 0; i < baseCount; i++) {
            bases[i] = new BaseClassTypeInfoModel(program, base.getAddress());
            base.advance();
        }
        return bases;
    }

    public ClassTypeInfo getParentAtOffset(long offset, boolean virtual)
        throws InvalidDataTypeException {
            validate();
            for (BaseClassTypeInfoModel base : bases) {
                    if (base.isVirtual() == virtual) {
                        if (base.getFlags().getOffset() == offset) {
                            return base.getClassModel();
                        }
                    }
                }
            return null;
    }

    private Map<AbstractClassTypeInfoModel, Set<AbstractClassTypeInfoModel>> getVirtualBases()
        throws InvalidDataTypeException {
            Map<AbstractClassTypeInfoModel, Set<AbstractClassTypeInfoModel>> baseMap =
                new LinkedHashMap<>();
            for (BaseClassTypeInfoModel base : bases) {
                AbstractClassTypeInfoModel parent = base.getClassModel();
                Set<AbstractClassTypeInfoModel> subSet = new LinkedHashSet<>();
                baseMap.put(parent, subSet);
                if (base.isVirtual()) {
                    baseMap.put(parent, Collections.singleton(parent));
                }
                if (parent.hasParent()) {
                    if (isVmi(parent)) {
                        VmiClassTypeInfoModel vmi = toVmi(parent);
                        for (ClassTypeInfo grandParent : vmi.getVirtualBases().keySet()) {
                            subSet.add(toSuper(grandParent));
                        }
                    } else {
                        // __si_class_type_info is virtual iff it's parent is virtual
                        if (base.isVirtual()) {
                            subSet.add(toSuper(parent.getParentModels()[0]));
                        }
                    }
                }
            } return baseMap;
    }

    private static void shrinkStruct(DataType dt, int length) {
        if (length > 0  && dt.getLength() > length) {
            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                while (struct.getLength() > length) {
                    struct.deleteAtOffset(length);
                }
            }
        }
    }

    private void addBase(Structure struct, BaseClassTypeInfoModel base, int maxLength)
        throws InvalidDataTypeException {
            AbstractClassTypeInfoModel parent = base.getClassModel();
            Structure parentStruct = parent.getSuperClassDataType();
            shrinkStruct(parentStruct, maxLength);
            replaceComponent(struct, parentStruct, SUPER+base.getName(), base.getOffset());
    }

    private void addVirtualBase(Structure struct, AbstractClassTypeInfoModel base,
        int offset, int maxLength) throws InvalidDataTypeException {
            Structure parentStruct = base.getSuperClassDataType();
            shrinkStruct(parentStruct, maxLength);
            replaceComponent(struct, parentStruct, SUPER+base.getName(), offset);
    }

    private boolean isVmi(ClassTypeInfo type) {
        return type instanceof VmiClassTypeInfoModel;
    }

    private VmiClassTypeInfoModel toVmi(ClassTypeInfo type) {
        return (VmiClassTypeInfoModel) type;
    }

    private AbstractClassTypeInfoModel toSuper(ClassTypeInfo type) {
        return (AbstractClassTypeInfoModel) type;
    }

    private void addBases(Structure struct) throws InvalidDataTypeException {
        Set<AbstractClassTypeInfoModel> subBases = new HashSet<>();
        VtableModel vtable = (VtableModel) getVtable();
        long[] offsets = vtable.getOffsetArray();
        Arrays.sort(offsets);
        int i = 0;
        Map<AbstractClassTypeInfoModel, Set<AbstractClassTypeInfoModel>> vBases =
            getVirtualBases();
        for (int j = 0; j < bases.length; j++) {
            BaseClassTypeInfoModel base = bases[j];
            AbstractClassTypeInfoModel parent = base.getClassModel();
            if (base.isVirtual()) {
                if (!subBases.contains(parent)) {
                    try {
                        int maxLength = ++i+1 == offsets.length ? -1 : (int) offsets[i];
                        addVirtualBase(struct, parent, (int) offsets[i], maxLength);
                        subBases.add(parent);
                    } catch (ArrayIndexOutOfBoundsException e) {
                        Msg.error(this, e);
                    }
                }
            } else {
                int maxLength = j+1 == bases.length ? -1 : bases[j+1].getOffset();
                addBase(struct, base, maxLength);
            }
            if (vBases.containsKey(parent)) {
                for (AbstractClassTypeInfoModel grandparent : vBases.get(parent)) {
                    if (!subBases.contains(grandparent)) {
                        int maxLength = ++i+1 == offsets.length ? -1 : (int) offsets[i];
                        addVirtualBase(struct, grandparent, (int) offsets[i], maxLength);
                        subBases.add(grandparent);
                    }
                }
                vBases.remove(parent);
            }
        }
    }

    @Override
    public Structure getClassDataType(boolean repopulate) throws InvalidDataTypeException {
        validate();
        if (getTypeName().contains(TypeInfoModel.STRUCTURE_NAME)) {
            return TypeInfoUtils.getDataType(program, getTypeName());
        }
        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = ClassTypeInfoUtils.getPlaceholderStruct(this, dtm);
        if (!ClassTypeInfoUtils.isPlaceholder(struct) && !repopulate) {
            return struct;
        }
        stashComponents(struct);
        struct.setDescription("");
        addBases(struct);
        addVptr(struct);
        if (repopulate && super.getSuperClassDataType() != null) {
            getSuperClassDataType(repopulate, struct);
        }
        fixComponents(struct);
        return resolveStruct(struct);
    }

    private void fixComponents(Structure struct) {
        for (DataTypeComponent comp : dtComps.keySet()) {
            if (comp.getOffset() != dtComps.get(comp)) {
                struct.replaceAtOffset(
                    dtComps.get(comp), comp.getDataType(),
                    comp.getLength(), comp.getFieldName(), comp.getComment());
                struct.clearComponent(comp.getOrdinal());
            }
        }
    }

    @Override
    protected Structure getSuperClassDataType() throws InvalidDataTypeException {
        return getSuperClassDataType(false, null);
    }
    
    private Structure getSuperClassDataType(boolean repopulate, DataType classDt)
        throws InvalidDataTypeException {
            validate();
            Structure struct = super.getSuperClassDataType();
            if (!ClassTypeInfoUtils.isPlaceholder(struct) &&!repopulate) {
                return struct;
            }
            struct = new StructureDataType(getName(), 0, program.getDataTypeManager());
            if (classDt != null) {
                struct.replaceWith(classDt);
            } else {
                struct.replaceWith(getClassDataType());
            }
            setSuperStructureCategoryPath(struct);
            Set<String> parents = new HashSet<>();
            for (Map.Entry<AbstractClassTypeInfoModel,Set<AbstractClassTypeInfoModel>> parent :
                getVirtualBases().entrySet()) {
                    parents.add(SUPER+parent.getKey().getName());
                    for (ClassTypeInfo grandparent : parent.getValue()) {
                        parents.add(SUPER+grandparent.getName());
                }
            }
            DataTypeComponent[] comps = struct.getComponents();
            for (DataTypeComponent comp : comps) {
                if (parents.contains(comp.getFieldName())) {
                    int ordinal = comp.getOrdinal();
                    int[] ordinals = IntStream.rangeClosed(ordinal, comps.length - 1).toArray();
                    struct.delete(ordinals);
                    break;
                }
            }
            comps = struct.getDefinedComponents();
            if (comps.length > 0) {
                int ordinal = comps[comps.length-1].getOrdinal();
                int[] ordinals = IntStream.rangeClosed(
                    ordinal+1, struct.getNumComponents() - 1).toArray();
                struct.delete(ordinals);
            }
            addVptr(struct);
            fixComponents(struct);
            return resolveStruct(struct);
    }

    private boolean validFieldName(String name) {
        return !name.startsWith(SUPER) && !name.equals("_vptr");
    }

    private void stashComponents(Structure struct) {
        if(dtComps.isEmpty()) {
            dtComps = new HashMap<>(struct.getNumDefinedComponents());
            for (DataTypeComponent comp : struct.getDefinedComponents()) {
                String fieldName = comp.getFieldName();
                if (fieldName != null && validFieldName(fieldName)) {
                    if (!comp.getDataType().isNotYetDefined()) {
                        dtComps.put(comp, comp.getOffset());
                    }
                }
            }
        }
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
     * @param MemBuffer
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

    public DataType getBaseArrayDataType() {
        int baseCount = getBaseCount();
        DataType base = BaseClassTypeInfoModel.getDataType(program.getDataTypeManager());
        return new ArrayDataType(base, baseCount, base.getLength(), program.getDataTypeManager());
    }

    public Address getBaseArrayAddress() {
        return address.add(getDataType().getComponent(BASE_ARRAY_ORDINAL).getOffset());
    }
}
