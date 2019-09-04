package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

/**
 * Model for the __offset_flags in the __base_class_type_info helper class.
 */
final class VmiOffsetFlagsModel {

    private static final String DATA_TYPE_NAME = "__offset_flags";
    private static final String DESCRIPTION = "Model for the vmi offset flags";

    protected static final int VIRTUAL_MASK = 1;
    protected static final int PUBLIC_MASK = 2;

    private Program program;
    private Address address;

    protected VmiOffsetFlagsModel(Program program, Address address) {
        this.program = program;
        this.address = address;
    }

    protected boolean isVirtual() {
        MemBuffer buf = new MemoryBufferImpl(program.getMemory(), address);
        return isVirtual(buf, program.getDataTypeManager());
    }

    protected boolean isPublic() {
        MemBuffer buf = new MemoryBufferImpl(program.getMemory(), address);
        return isPublic(buf, program.getDataTypeManager());
    }

    protected long getOffset() {
        MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), address);
        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = (Structure) getDataType(dtm);
        DataTypeComponent comp;
        if (dtm.getDataOrganization().isBigEndian()) {
            comp = struct.getComponent(0);
        } else {
            comp = struct.getComponent(1);
        }
        try {
            return buf.getBigInteger(comp.getOffset(), comp.getLength(), true).longValue();
        } catch (MemoryAccessException e) {
            return 0;
        }
    }

    protected static boolean isVirtual(MemBuffer buf, DataTypeManager dtm) {
        Structure struct = (Structure) getDataType(dtm);
        DataTypeComponent flagsComponent;
        if (dtm.getDataOrganization().isBigEndian()) {
            flagsComponent = struct.getComponent(1);
        } else {
            flagsComponent = struct.getComponent(0);
        }
        Enum flags = (Enum) flagsComponent.getDataType();
        Scalar value = (Scalar) flags.getValue(buf, flagsComponent.getDefaultSettings(), flags.getLength());
        return value.testBit(0);
    }

    protected static boolean isPublic(MemBuffer buf, DataTypeManager dtm) {
        Structure struct = (Structure) getDataType(dtm);
        DataTypeComponent flagsComponent;
        if (dtm.getDataOrganization().isBigEndian()) {
            flagsComponent = struct.getComponent(1);
        } else {
            flagsComponent = struct.getComponent(0);
        }
        Enum flags = (Enum) flagsComponent.getDataType();
        Scalar value = (Scalar) flags.getValue(buf, flagsComponent.getDefaultSettings(), flags.getLength());
        return value.testBit(1);
    }

    protected static DataType getDataType(DataTypeManager dtm) {
        StructureDataType struct = new StructureDataType(VmiClassTypeInfoModel.SUB_PATH, DATA_TYPE_NAME, 0, dtm);
        if (dtm.getDataOrganization().isBigEndian()) {
            struct.add(OffsetShiftDataType.dataType.clone(dtm), "__offset", null);
            struct.add(getFlags(dtm), "__flags", null);
        } else {
            struct.add(getFlags(dtm), "__flags", null);
            struct.add(OffsetShiftDataType.dataType.clone(dtm), "__offset", null);
        }
        struct.setInternallyAligned(true);
        DataType base = GnuUtils.isLLP64(dtm) ? LongLongDataType.dataType.clone(dtm)
            : LongDataType.dataType.clone(dtm);
        int alignment = dtm.getDataOrganization().getAlignment(base, struct.getLength());
        struct.setMinimumAlignment(alignment);
        struct.setDescription(DESCRIPTION);
        return dtm.resolve(struct, KEEP_HANDLER);
    }
    
    private static DataType getFlags(DataTypeManager dtm) {
        EnumDataType flags = new EnumDataType(VmiClassTypeInfoModel.SUB_PATH, "offset_flags", 1, dtm);
        flags.add("__virtual_mask", VIRTUAL_MASK);
        flags.add("__public_mask", PUBLIC_MASK);
        // the offset shift parameter is meaningless here
        return dtm.resolve(flags, KEEP_HANDLER);
    }
}