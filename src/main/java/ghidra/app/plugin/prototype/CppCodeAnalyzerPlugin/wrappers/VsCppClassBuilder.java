package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers;

import static ghidra.program.model.data.Undefined.isUndefined;

import java.util.List;
import java.util.Map;

import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.symbol.Symbol;

public class VsCppClassBuilder extends AbstractCppClassBuilder {

    private static final String VFPTR = "_vfptr";
    private static final String VBPTR = "_vbptr";

    public VsCppClassBuilder(RttiModelWrapper type) {
        super(type);
    }

    @Override
    protected AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent) {
        return new VsCppClassBuilder((RttiModelWrapper) parent);
    }

    @Override
    protected void addVptr() {
        try {    
            addVfptr();
            addVbptr();
        } catch (InvalidDataTypeException e) {
            return;
        }
    }

    private int getVbValue() throws InvalidDataTypeException {
        List<Symbol> symbols = getProgram().getSymbolTable().getSymbols(
            "`vbtable'", getType().getGhidraClass());
        if (symbols.isEmpty() || symbols.size() > 1) {
            return -1;
        }
        MemBuffer buf = new MemoryBufferImpl(getProgram().getMemory(), symbols.get(0).getAddress());
        try {
            return buf.getInt(0);
        } catch (MemoryAccessException e) {
            return -1;
        }
    }

    private void addVfptr() {
        ClassTypeInfo type = getType();
        try {
            type.getVtable().validate();
            if (getVbValue() >= 0) {
                // we don't have one
                return;
            }
        } catch (InvalidDataTypeException e) {
            return;
        }
        DataType vfptr = ClassTypeInfoUtils.getVptrDataType(getProgram(), type);
        DataTypeComponent comp = struct.getComponentAt(0);
        if (comp == null || isUndefined(comp.getDataType())) {
            if (vfptr != null) {
                clearComponent(struct, getProgram().getDefaultPointerSize(), 0);
                struct.insertAtOffset(0, vfptr, getProgram().getDefaultPointerSize(), VFPTR, null);
            }
        } else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
            clearComponent(struct, getProgram().getDefaultPointerSize(), 0);
            struct.insertAtOffset(0, vfptr, getProgram().getDefaultPointerSize(), VFPTR, null);
        }
    }

    private void addVbptr() throws InvalidDataTypeException {
        RttiModelWrapper type = (RttiModelWrapper) getType();
        if (type.getVirtualParents().isEmpty()) {
            return;
        }
        Program program = getProgram();
        int pointerSize = program.getDefaultPointerSize();
        int offset;
        if (getVbValue() >= 0) {
            offset = 0;
        } else {
            offset = pointerSize;
        }
        DataType vbptr = program.getDataTypeManager().getPointer(
            IntegerDataType.dataType, pointerSize);
        DataTypeComponent comp = struct.getComponentAt(1);
        if (comp == null || isUndefined(comp.getDataType())) {
            if (vbptr != null) {
                clearComponent(struct, pointerSize, offset);
                struct.insertAtOffset(offset, vbptr, pointerSize, VBPTR, null);
            }
        } else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
            clearComponent(struct, pointerSize, offset);
            struct.insertAtOffset(offset, vbptr, pointerSize, VBPTR, null);
        }
    }

    @Override
    protected Map<ClassTypeInfo, Integer> getBaseOffsets() throws InvalidDataTypeException {
        RttiModelWrapper type = (RttiModelWrapper) getType();
        return type.getBaseOffsets();
    }
}
