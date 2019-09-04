package ghidra.app.cmd.data.rtti.gcc.vtable;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeDisplayOptions;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.docking.settings.Settings;

import static ghidra.app.cmd.data.rtti.gcc.VtableUtils.getNumPtrDiffs;

import java.util.ArrayList;
import java.util.List;

public class VtablePrefixDataType extends DynamicDataType {

    public static final String DATA_TYPE_NAME = "vtable_prefix";
    public static final String DESCRIPTION = "Initial part of a vtable";

    // some commonly used strings
    private static final String TYPEINFO = "typeinfo";
    private static final String THIS_TYPEINFO = "this::" + TYPEINFO;

    public static final VtablePrefixDataType dataType = new VtablePrefixDataType();

    public VtablePrefixDataType() {
        this(null);
    }
    
    public VtablePrefixDataType(DataTypeManager dtm) {
        super(DATA_TYPE_NAME, dtm);
    }

    /**
     * This gets the vtable structure for the indicated program.
     * 
     * @param program the program which will contain this data type.
     * @return the vtable structure.
     */

    @Override
    protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
        Program program = buf.getMemory().getProgram();
        int pointerSize = program.getDefaultPointerSize();
        DataTypeManager dtm = program.getDataTypeManager();
        DataType ptrdiff_t = GnuUtils.getPtrDiff_t(dtm);
        List<DataTypeComponent> comps = new ArrayList<>();
        int numPtrDiffs = getNumPtrDiffs(buf);
        if (numPtrDiffs == 0) {
            return null;
        }
        ArrayDataType array = new ArrayDataType(ptrdiff_t, numPtrDiffs, ptrdiff_t.getLength());
        comps.add(GnuUtils.getComponent(array, this, null, null));
        comps.add(GnuUtils.getComponent(
            new PointerDataType(null, pointerSize, dtm), this, comps.get(0), TYPEINFO, THIS_TYPEINFO));
        Address tableAddress = buf.getAddress().add(comps.get(1).getEndOffset()+1);
        int tableSize = VtableUtils.getFunctionTableLength(program, tableAddress);
        if (tableSize <= 0) {
            return comps.toArray(new DataTypeComponent[comps.size()]);
        }
        DataType vptr = GnuUtils.getVptr(dtm);
        ArrayDataType table = new ArrayDataType(vptr, tableSize, program.getDefaultPointerSize(), dtm);
        comps.add(GnuUtils.getComponent(table, this, comps.get(1), null, null));
        return comps.toArray(new DataTypeComponent[comps.size()]);
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        return null;
    }
    
    @Override
    public final String getRepresentation(MemBuffer buf, Settings settings, int length) {
        if (isNotYetDefined()) {
            return "<Empty-Structure>";
        }
        return "";
    }

    @Override
    public String getMnemonic(Settings settings) {
        return DATA_TYPE_NAME;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        if (dtm == getDataTypeManager()) {
            return this;
        } return new VtablePrefixDataType(dtm);
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    private long getOffsetValue(MemBuffer buf, int offset) {
        DataTypeManager dtm = buf.getMemory().getProgram().getDataTypeManager();
        int ptrDiffSize = GnuUtils.getPtrDiffSize(dtm);
        try {
            return buf.getBigInteger(offset, ptrDiffSize, true).longValue();
        } catch (MemoryAccessException e) {
            return 0;
        }
    }

    /**
     * Gets the offset_to_top value.
     * @param buf
     * @return the offset_to_top value.
     */
    public long getOffsetToTop(MemBuffer buf) {
        DataTypeComponent comp = getNumComponents(buf) == 4 ? getComponent(1, buf)
            : getComponent(0, buf);
        return getOffsetValue(buf, comp.getOffset());
    }


    /**
     * Gets the offset_to_virtual_base value.
     * @param buf
     * @return the offset_to_virtual_base value.
     */
    public long getOffsetToVirtualBase(MemBuffer buf) {
        if (getNumComponents(buf) < 4) {
            return 0;
        } return getOffsetValue(buf, getComponent(0, buf).getOffset());
    }

    @Override
    public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings,
        int len, DataTypeDisplayOptions options, int offcutOffset) {
            DataTypeComponent comp = getComponentAt(offcutOffset, buf);
            MemoryBufferImpl subBuffer = new MemoryBufferImpl(
                buf.getMemory(), buf.getAddress().add(comp.getOffset()));
            if (comp.getDataType() instanceof Array) {
                return comp.getDataType().getDefaultOffcutLabelPrefix(
                    subBuffer, settings, comp.getLength(),
                    options, offcutOffset - comp.getOffset());
            } return comp.getDataType().getRepresentation(subBuffer, settings, comp.getLength());
    }

}