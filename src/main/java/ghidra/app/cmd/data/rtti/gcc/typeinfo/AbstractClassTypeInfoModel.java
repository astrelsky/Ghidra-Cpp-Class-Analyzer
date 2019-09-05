package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.AbstractTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.vtable.VtableDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static ghidra.program.model.data.Undefined.isUndefined;
import static ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils.getDataTypePath;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;

/**
 * Base Model for __class_type_info and its derivatives.
 */
public abstract class AbstractClassTypeInfoModel extends AbstractTypeInfoModel implements ClassTypeInfo {

    private VtableModel vtable = null;

    protected AbstractClassTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    private static String getUniqueTypeName(ClassTypeInfo type) throws InvalidDataTypeException {
        StringBuilder builder = new StringBuilder(type.getTypeName());
        for (ClassTypeInfo parent : type.getParentModels()) {
            builder.append(parent.getTypeName());
        }
        return builder.toString();
    }

    @Override
    public String getUniqueTypeName() throws InvalidDataTypeException {
        return getUniqueTypeName(this);
    }

    @Override
    public VtableModel getVtable(TaskMonitor monitor) throws InvalidDataTypeException {
        if (vtable != null) {
            return vtable;
        }
        SymbolTable table = program.getSymbolTable();
        for (Symbol symbol : table.getSymbols(VtableModel.SYMBOL_NAME, getGhidraClass())) {
            Data data = program.getListing().getDataAt(symbol.getAddress());
            if (data != null && data.getDataType() instanceof VtableDataType) {
                vtable = (VtableModel) data.getValue();
                try {
                    vtable.validate();
                    return vtable;
                } catch (InvalidDataTypeException e) {
                    continue;
                }
            }
        }
        try {
            vtable = (VtableModel) ClassTypeInfoUtils.findVtable(program, address, monitor);
        } catch (CancelledException e) {
            vtable = VtableModel.INVALID;
        }
        return vtable;
    }

    @Override
    public boolean isAbstract() throws InvalidDataTypeException {
        for (Function[] functionTable : getVtable().getFunctionTables()) {
            for (Function function : functionTable) {
                if (function == null || function.getName().equals(PURE_VIRTUAL_FUNCTION_NAME)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public GhidraClass getGhidraClass() throws InvalidDataTypeException {
        validate();
        if (!(namespace instanceof GhidraClass)) {
            try {
                namespace = NamespaceUtils.convertNamespaceToClass(namespace);
            } catch (InvalidInputException e) {
                Msg.error(this, e);
                return null;
            }
        } return (GhidraClass) namespace;
    }

    protected void setSuperStructureCategoryPath(Structure struct)
        throws InvalidDataTypeException {
            try {
                struct.setCategoryPath(getClassDataType().getCategoryPath());
                struct.setName(SUPER+struct.getName());
            } catch (InvalidNameException | DuplicateNameException e) {
                Msg.error(
                    this, "Failed to change placeholder struct "+getName()+"'s CategoryPath", e);
            }
    }

    protected Structure getSuperClassDataType() throws InvalidDataTypeException {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType struct = dtm.getDataType(getDataTypePath(this).getCategoryPath(), SUPER+getName());
        if (struct != null) {
            return (Structure) struct;
        } return null;
    }

    private void clearComponent(Structure struct, int length, int offset) {
        for (int size = 0; size < length;) {
            if (offset >= struct.getLength()) {
                break;
            }
            DataTypeComponent comp = struct.getComponentAt(offset);
            if (comp!= null) {
                size += comp.getLength();
            } else {
                size++;
            }
            struct.deleteAtOffset(offset);
        }
    }

    protected void replaceComponent(Structure struct, Structure parent, String name, int offset) {
        clearComponent(struct, parent.getLength(), offset);
        struct.insertAtOffset(offset, parent, parent.getLength(), name, null);
    }

    protected void addVptr(Structure struct) throws InvalidDataTypeException {
        DataTypeComponent comp = struct.getComponentAt(0);
        if (comp == null || isUndefined(comp.getDataType())) {
            Vtable subVtable = getVtable();
            try {
                subVtable.validate();
            } catch (InvalidDataTypeException e) {
                return;
            }
            int pointerSize = program.getDefaultPointerSize();
            DataTypeManager dtm = program.getDataTypeManager();
            DataType vptr = dtm.getPointer(VoidDataType.dataType);
            if (struct.getLength() <= 1) {
                struct.add(
                    vptr, pointerSize, "_vptr", null);
            } else {
                struct.replace(0,
                    vptr, pointerSize, "_vptr", null);
            }
        }
    }

    protected static Structure resolveStruct(Structure struct) {
        DataTypeManager dtm = struct.getDataTypeManager();
        return (Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    @Override
    public DataType getRepresentedDataType() throws InvalidDataTypeException {
        return getClassDataType(false);
    }
}