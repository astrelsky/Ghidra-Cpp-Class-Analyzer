package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.DataType;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.docking.settings.Settings;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Model for Virtual Multiple Inheritance Class Type Info
 */
public final class VmiClassTypeInfoDataType extends DynamicDataType {
    
    public static final String DATA_TYPE_NAME = "__vmi_class_type_info";

    public static final String TYPE_STRING = "N10__cxxabiv121__vmi_class_type_infoE";
    private static final String DESCRIPTION = "Model for Virtual Multiple Inheritance Class Type Info";
    private static final String FLAGS_NAME = "__flags";
    private static final String BASE_COUNT_NAME = "__base_count";
    private static final String ARRAY_NAME = "__base_info";

    public static final String DIAMOND_MASK_NAME = "__diamond_shaped_mask";
    public static final String NON_DIAMOND_MASK_NAME = "__non_diamond_repeat_mask";

    public enum Flags {
        NON_DIAMOND,
        DIAMOND,
        NON_PUBLIC,
        PUBLIC,
        UNKNOWN
    }

    public static final VmiClassTypeInfoDataType dataType = new VmiClassTypeInfoDataType();

    public VmiClassTypeInfoDataType() {
        this(null);
    }

    public VmiClassTypeInfoDataType(DataTypeManager dtm) {
        super(DATA_TYPE_NAME, dtm);
    }

    @Override
    public String getName() {
        return DATA_TYPE_NAME;
    }

    private static DataType getFlags(DataTypeManager dtm, CategoryPath path) {
        EnumDataType flags = new EnumDataType(path, "__flags_masks", IntegerDataType.dataType.getLength(), dtm);

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
            DataTypeComponent comp = getComponent(1, buf);
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
     * Gets the value of this datatypes's __base_count
     * @param MemBuffer
     * @return the value of this datatypes's __base_count
     */
    public int getBaseCount(MemBuffer buf) {
        DataTypeComponent baseComponent = getComponent(2, buf);
        IntegerDataType baseCount = (IntegerDataType) baseComponent.getDataType();
        MemBuffer tmpBuf = new MemoryBufferImpl(buf.getMemory(), buf.getAddress().add(baseComponent.getOffset()));
        Scalar value = (Scalar) baseCount.getValue(tmpBuf, baseComponent.getDefaultSettings(), baseCount.getLength());
        long result = value.getUnsignedValue();
        return result > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) result;
    }

    private DataTypeComponent getBaseArrayComponent(MemBuffer buf, DataTypeComponent prev, DataTypeManager dtm) {
        buf = new MemoryBufferImpl(buf.getMemory(), buf.getAddress().add(prev.getOffset()));
        int baseCount;
        try {
            baseCount = buf.getInt(0);
        } catch (MemoryAccessException e) {
            baseCount = 0;
        }
        DataType baseDt = BaseClassTypeInfoModel.getDataType(dtm);
        ArrayDataType array = baseCount <= 0 ? new ArrayDataType(baseDt, 1, baseDt.getLength(), dtm)
                : new ArrayDataType(baseDt, baseCount, baseDt.getLength(), dtm);
        return GnuUtils.getComponent(array, this, prev, ARRAY_NAME, null);
    }

    @Override
    protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
        DataTypeManager dtm = buf.getMemory().getProgram().getDataTypeManager();
        DataTypeComponent[] comps = new DataTypeComponent[4];
        // FLAGS_OFFSET is the size of the class type info and where the flags start
        comps[0] = GnuUtils.getComponent(ClassTypeInfoModel.getDataType(dtm), this,
                AbstractTypeInfoModel.SUPER + ClassTypeInfoModel.STRUCTURE_NAME, null);
        comps[1] = GnuUtils.getComponent(getFlags(dtm, getCategoryPath()), this, comps[0], FLAGS_NAME, null);
        comps[2] = GnuUtils.getComponent(
            IntegerDataType.dataType.clone(dtm), this, comps[1], BASE_COUNT_NAME, null);
        comps[3] = getBaseArrayComponent(buf, comps[2], dtm);
        return comps;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        if (dtm == getDataTypeManager()) {
            return this;
        }
        return new VmiClassTypeInfoDataType(dtm);
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getMnemonic(Settings settings) {
        return DATA_TYPE_NAME;
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        return null;
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        return new VmiClassTypeInfoModel(buf.getMemory().getProgram(), buf.getAddress());
    }

    /**
     * @see getReplacementBaseType
     * @param DataTypeManager
     */
    public static DataType getReplacementBaseType(DataTypeManager dtm) {
        DataType existingDt = dtm.getDataType(GnuUtils.getCxxAbiCategoryPath(), DATA_TYPE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        StructureDataType struct = new StructureDataType(
            GnuUtils.getCxxAbiCategoryPath(), DATA_TYPE_NAME, 0, dtm);
        struct.add(
            ClassTypeInfoModel.getDataType(dtm),
            AbstractTypeInfoModel.SUPER+ClassTypeInfoModel.STRUCTURE_NAME, null);
        struct.add(getFlags(dtm, VmiClassTypeInfoModel.SUB_PATH), FLAGS_NAME, null);
        struct.add(
            IntegerDataType.dataType.clone(dtm), BASE_COUNT_NAME, null);
        struct.setFlexibleArrayComponent(BaseClassTypeInfoModel.getDataType(dtm), ARRAY_NAME, null);
        struct.setDescription(DESCRIPTION);
        DataType result = dtm.resolve(struct, KEEP_HANDLER);
        return result.getLength() <= 1 ? dtm.resolve(struct, REPLACE_HANDLER) : result;
    }

    @Override
    public DataType getReplacementBaseType() {
        return getReplacementBaseType(getDataTypeManager());
    }
}
