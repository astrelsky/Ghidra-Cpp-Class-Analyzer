package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import java.util.*;
import java.util.stream.IntStream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;

import static ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoDataType.Flags;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.getCxxAbiCategoryPath;

/**
 * Model for the __vmi_class_type_info class.
 */
public class VmiClassTypeInfoModel extends AbstractClassTypeInfoModel {

    public static final String STRUCTURE_NAME = "__vmi_class_type_info";

    public static final String ID_STRING = "N10__cxxabiv121__vmi_class_type_infoE";

    private VmiClassTypeInfoDataType typeInfoDataType;

    protected static final CategoryPath SUB_PATH =
        new CategoryPath(getCxxAbiCategoryPath(), STRUCTURE_NAME);

    private BaseClassTypeInfoModel[] bases;
    private Flags flags;
    private Map<DataTypeComponent, Integer> dtComps = Collections.emptyMap();

    public VmiClassTypeInfoModel(Program program, Address address) {
        super(program, address);
        this.typeInfoDataType = (VmiClassTypeInfoDataType) getDataType(program.getDataTypeManager());
        this.bases = getBases();
        this.flags = typeInfoDataType.getFlags(getBuffer());
    }

    @Override
    public DataType getDataType() {
        return typeInfoDataType;
    }

    public Flags getFlags() {
        return flags;
    }

    /**
     * @see ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel#getDataType(DataTypeManager)
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return VmiClassTypeInfoDataType.dataType.clone(dtm);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    private Address getArrayAddress() {
        MemBuffer buf = getBuffer();
        DataTypeComponent arrayComponent = typeInfoDataType.getComponent(3, buf);
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

    private BaseClassTypeInfoModel[] getBases() {
        if (bases != null) {
            return bases;
        }
        BaseClassTypeInfoModel base = new BaseClassTypeInfoModel(program, getArrayAddress());
        int baseCount = typeInfoDataType.getBaseCount(getBuffer());
        bases = new BaseClassTypeInfoModel[baseCount];
        for (int i = 0; i < baseCount; i++) {
            bases[i] = new BaseClassTypeInfoModel(program, base.getAddress());
            base.advance();
        } return bases;
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
                    int maxLength = ++i+1 == offsets.length ? -1 : (int) offsets[i];
                    addVirtualBase(struct, parent, (int) offsets[i], maxLength);
                    subBases.add(parent);
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
            DataType result = TypeInfoUtils.getDataType(program, getTypeName());
            if (result instanceof DynamicDataType) {
                return (Structure) ((VmiClassTypeInfoDataType) result).getReplacementBaseType();
            } return (Structure) result;
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
}
