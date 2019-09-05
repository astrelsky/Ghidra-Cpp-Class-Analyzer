package ghidra.app.cmd.data.rtti.gcc.vtable;

import java.util.ArrayList;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.vtable.VtablePrefixDataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeDisplayOptions;
import ghidra.program.model.data.ReadOnlyDataTypeComponent;
import ghidra.program.model.listing.Program;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.app.cmd.data.rtti.gcc.VtableUtils.getNumPtrDiffs;

public class VtableDataType extends DynamicDataType {

    public static final String DATA_TYPE_NAME = "vtable";
    public static final String DESCRIPTION = "Dynamically sized vtable_prefix array";

    // some commonly used strings
    protected static final String PREFIX = "prefix";
    protected static final String INHERITED = "inherited";

    private VtablePrefixDataType base;
    private Vtable model = Vtable.NO_VTABLE;
    private int elementCount = 0;
    public static final VtableDataType dataType = new VtableDataType();

    public VtableDataType() {
        this(null);
    }

    public VtableDataType(DataTypeManager dtm) {
        super(DATA_TYPE_NAME, dtm);
        this.base = (VtablePrefixDataType) VtablePrefixDataType.dataType.clone(dtm);
    }
    
    public VtableDataType(DataTypeManager dtm, VtableModel model) {
        this(dtm);
        this.model = model;
    }

    public VtableDataType(DataTypeManager dtm, VtableModel model, int elementCount) {
        this(dtm, model);
        this.elementCount = elementCount;
    }

    private DataTypeComponent getPrefixasComponent(MemBuffer buf, DataTypeComponent prev, String comment) {
        if (prev == null) {
            return new ReadOnlyDataTypeComponent(base, this, base.getLength(buf, 0), 0, 0, PREFIX, comment);
        }
        int offset = prev.getEndOffset() + 1;
        MemBuffer tmpBuffer = new MemoryBufferImpl(buf.getMemory(), buf.getAddress().add(offset));
        return new ReadOnlyDataTypeComponent(base, this, base.getLength(tmpBuffer, 0),
            prev.getOrdinal() + 1, offset, PREFIX, comment);
    }

    private Address getTypeInfoAddress(MemBuffer buf) {
        int numPtrDiffs = getNumPtrDiffs(buf);
        Program program = buf.getMemory().getProgram();
        int ptrDiffSize = GnuUtils.getPtrDiffSize(program.getDataTypeManager());
        Address pointerAddress = buf.getAddress().add(numPtrDiffs *ptrDiffSize);
        return getAbsoluteAddress(program, pointerAddress);
    }

    @Override
    protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
        ArrayList<DataTypeComponent> comps = new ArrayList<DataTypeComponent>();
        Address tiAddress = getTypeInfoAddress(buf);
        if (tiAddress == null) {
            return null;
        }
        comps.add(getPrefixasComponent(buf, null, null));
        if (elementCount > 0) {
            for (int i = 1; i < elementCount; i++) {
                comps.add(getPrefixasComponent(buf, getPrev(comps), INHERITED));
            }
        } else {
            addInheritedComponents(buf, comps, tiAddress);
        }
        return comps.toArray(new DataTypeComponent[comps.size()]);
    }

    private DataTypeComponent getPrev(ArrayList<DataTypeComponent> comps) {
        return comps.get(comps.size() - 1);
    }

    private void addInheritedComponents(MemBuffer buf, ArrayList<DataTypeComponent> comps,
        Address tiAddress) {
            MemoryBufferImpl tmpBuffer = new MemoryBufferImpl(buf.getMemory(), buf.getAddress());
            while (true) {
                try {
                    tmpBuffer.advance((getPrev(comps)).getLength());
                }
                catch (AddressOverflowException e) {
                    break;
                }
                if (!tiAddress.equals(getTypeInfoAddress(tmpBuffer))) {
                    break;
                }
                comps.add(getPrefixasComponent(buf, getPrev(comps), INHERITED));
            }
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        try {
            model.validate();
            return model;
        } catch (InvalidDataTypeException | NullPointerException e) {
            VtableModel vtable = 
                new VtableModel(buf.getMemory().getProgram(), buf.getAddress());
            try {
                vtable.validate();
                return vtable;
            } catch (InvalidDataTypeException e2) {}
        }
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
        } return new VtableDataType(dtm);
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    private MemBuffer getBufferForOffset(MemBuffer buf, int ordinal) {
        DataTypeComponent comp = getComponent(ordinal, buf);
        return new DumbMemBufferImpl(buf.getMemory(), buf.getAddress().add(comp.getOffset()));
    }

    /**
     * Gets the offset_to_top value.
     * @param buf
     * @param ordinal the vtable_prefix ordinal
     * @return the offset_to_top value.
     */
    public long getOffsetToTop(MemBuffer buf, int ordinal) {
        if (getNumComponents(buf) <= ordinal) {
            return 0;
        } MemBuffer dumbBuf = getBufferForOffset(buf, ordinal);
        return VtablePrefixDataType.dataType.getOffsetToTop(dumbBuf);
    }

    /**
     * Gets the offset_to_virtual_base value.
     * @param buf
     * @param ordinal the vtable_prefix ordinal
     * @return the offset_to_virtual_base value.
     */
    public long getOffsetToVirtualBase(MemBuffer buf, int ordinal) {
        if (getNumComponents(buf) <= ordinal) {
            return 0;
        } MemBuffer dumbBuf = getBufferForOffset(buf, ordinal);
        return VtablePrefixDataType.dataType.getOffsetToVirtualBase(dumbBuf);
    }

    @Override
    public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings,
        int len, DataTypeDisplayOptions options, int offcutOffset) {
            DataTypeComponent comp = getComponentAt(offcutOffset, buf);
            MemoryBufferImpl subBuffer = new MemoryBufferImpl(
                buf.getMemory(), buf.getAddress().add(comp.getOffset()));
            return comp.getDataType().getDefaultOffcutLabelPrefix(
                subBuffer, settings, comp.getLength(), options, offcutOffset - comp.getOffset());
    }
    
}