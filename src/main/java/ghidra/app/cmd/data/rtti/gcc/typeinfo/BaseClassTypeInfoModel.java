package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory.getTypeInfo;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Model for the __base_type_info helper class.
 */
final class BaseClassTypeInfoModel {

    private static final String DESCRIPTION =
        "Helper data type for the __base_class_type_info array";
    protected static final String STRUCTURE_NAME = "__base_class_type_info";
    protected static final int FLAGS_ORDINAL = 1;

    private Program program;
    private MemoryBufferImpl buf;
    private DataTypeManager dtm;

    protected BaseClassTypeInfoModel(Program program, Address address) {
        this.program = program;
        this.buf = new MemoryBufferImpl(program.getMemory(), address);
        this.dtm = program.getDataTypeManager();
    }

    /**
     * Returns true if this base class is inherited virtually.
     * @return true if this base class is inherited virtually.
     */
    public boolean isVirtual() {
        Structure struct = (Structure) getDataType();
        int offset = struct.getComponent(1).getOffset();
        MemBuffer tmpBuf = new DumbMemBufferImpl(buf.getMemory(), buf.getAddress().add(offset));
        return VmiOffsetFlagsModel.isVirtual(tmpBuf, dtm);
    }

    /**
     * Returns true if this base class is inherited publically.
     * @return true if this base class is inherited publically.
     */
    public boolean isPublic() {
        Structure struct = (Structure) getDataType();
        int offset = struct.getComponent(1).getOffset();
        MemBuffer tmpBuf = new DumbMemBufferImpl(buf.getMemory(), buf.getAddress().add(offset));
        return VmiOffsetFlagsModel.isPublic(tmpBuf, dtm);
    }

    /**
     * Gets the value of this base class's offset.
     * @return the value of this base class's offset.
     */
    public int getOffset() {
        return (int) getFlags().getOffset();
    }

    public DataType getDataType() {
        return getDataType(dtm);
    }

    protected Address getAddress() {
        return buf.getAddress();
    }

    protected VmiOffsetFlagsModel getFlags() {
        Structure struct = (Structure) getDataType();
        int offset = struct.getComponent(1).getOffset();
        return new VmiOffsetFlagsModel(program, buf.getAddress().add(offset));
    }

    /**
     * @see ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel#getDataType(DataTypeManager)
     */
    public static DataType getDataType(DataTypeManager dtm) {
        DataType superDt = ClassTypeInfoModel.getPointer(dtm);
        DataType existingDt = dtm.getDataType(superDt.getCategoryPath(), STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        DataType flags = VmiOffsetFlagsModel.getDataType(dtm);
        StructureDataType struct = new StructureDataType(superDt.getCategoryPath(), STRUCTURE_NAME, 0, dtm);
        struct.add(superDt, superDt.getLength(), "super___class_type_info", null);
        struct.add(flags, flags.getLength(), "__offset_flags", null);
        struct.setInternallyAligned(true);
        struct.adjustInternalAlignment();
        struct.setDescription(DESCRIPTION);
        DataType result = dtm.resolve(struct, KEEP_HANDLER);
        return result.getLength() <= 1 ? dtm.resolve(struct, REPLACE_HANDLER) : result;
    }

    protected Address getClassAddress() {
        Pointer pointer = ClassTypeInfoModel.getPointer(dtm);
        return (Address) pointer.getValue(buf, pointer.getDefaultSettings(), -1);
    }

    protected AbstractClassTypeInfoModel getClassModel() {
        return (AbstractClassTypeInfoModel) getTypeInfo(program, getClassAddress());
    }

    protected String getName() throws InvalidDataTypeException {
        return getClassModel().getName();
    }

    protected void advance() {
        try {
            this.buf.advance(getDataType().getLength());
        } catch (AddressOverflowException e) {
            Msg.error(this, e);
        }
    }
}
