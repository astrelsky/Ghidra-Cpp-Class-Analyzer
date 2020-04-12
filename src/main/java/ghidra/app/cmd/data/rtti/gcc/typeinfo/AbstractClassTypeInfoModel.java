package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Collections;
import java.util.Set;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.AbstractTypeInfoModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;

/**
 * Base Model for __class_type_info and its derivatives.
 */
abstract class AbstractClassTypeInfoModel extends AbstractTypeInfoModel implements ClassTypeInfo {

    protected VtableModel vtable = null;
    private GccCppClassBuilder builder;

    protected AbstractClassTypeInfoModel(Program program, Address address) {
        super(program, address);
        builder = new GccCppClassBuilder(this);
    }

    private static String getUniqueTypeName(ClassTypeInfo type) {
        StringBuilder builder = new StringBuilder(type.getTypeName());
        for (ClassTypeInfo parent : type.getParentModels()) {
            builder.append(parent.getTypeName());
        }
        return builder.toString();
    }

    @Override
    public String getUniqueTypeName() {
        return getUniqueTypeName(this);
    }

    @Override
    public final Structure getClassDataType() {
        if (getTypeName().contains(TypeInfoModel.STRUCTURE_NAME)) {
            return TypeInfoUtils.getDataType(program, getTypeName());
        }
        return builder.getDataType();
    }

    @Override
    public VtableModel getVtable(TaskMonitor monitor) {
        if (vtable != null) {
            return vtable;
        }
        SymbolTable table = program.getSymbolTable();
        for (Symbol symbol : table.getSymbols(VtableModel.SYMBOL_NAME, getGhidraClass())) {
			final VtableModel tmpVtable =
				VtableModel.getVtable(program, symbol.getAddress(), this);
			if (Vtable.isValid(tmpVtable)) {
				vtable = tmpVtable;
				return vtable;
			}
        }
        try {
            vtable = (VtableModel) ClassTypeInfoUtils.findVtable(program, address, monitor);
        } catch (CancelledException e) {
            vtable = VtableModel.NO_VTABLE;
        }
        return vtable;
    }

    @Override
    public boolean isAbstract() {
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
    public GhidraClass getGhidraClass() {
        if (!(namespace instanceof GhidraClass)) {
            try {
				Integer id = null;
				if (program.getCurrentTransaction() == null) {
					id = program.startTransaction("creating GhidraClass for "+getName());
				}
                if (namespace.getSymbol().checkIsValid()) {
                    namespace = NamespaceUtils.convertNamespaceToClass(namespace);
                } else {
                    namespace = TypeInfoUtils.getNamespaceFromTypeName(program, typeName);
                    namespace = NamespaceUtils.convertNamespaceToClass(namespace);
				}
				if (id != null) {
					program.endTransaction(id, true);
				}
            } catch (InvalidInputException e) {
                Msg.error(this, e);
                return null;
            }
        } return (GhidraClass) namespace;
    }

    @Override
    public Set<ClassTypeInfo> getVirtualParents() {
        return Collections.emptySet();
    }

}