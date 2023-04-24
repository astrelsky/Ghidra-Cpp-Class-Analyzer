package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.Collections;
import java.util.Set;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import static ghidra.app.cmd.data.rtti.GnuVtable.PURE_VIRTUAL_FUNCTION_NAME;

/**
 * Base Model for __class_type_info and its derivatives.
 */
public abstract class AbstractClassTypeInfoModel extends AbstractTypeInfoModel
		implements ClassTypeInfo {

	protected GnuVtable vtable = null;
	private GccCppClassBuilder builder;

	protected AbstractClassTypeInfoModel(Program program, Address address) {
		super(program, address);
		builder = new GccCppClassBuilder(this);
	}

	@Override
	public final Structure getClassDataType() {
		DataTypeManager dtm = program.getDataTypeManager();
		if (getTypeName().contains(TypeInfoModel.STRUCTURE_NAME)) {
			// this doesn't occur often to the string switch statement is ok
			switch (getTypeName()) {
				case ArrayTypeInfoModel.ID_STRING:
					return (Structure) ArrayTypeInfoModel.getDataType(dtm);
				case ClassTypeInfoModel.ID_STRING:
					return (Structure) ClassTypeInfoModel.getDataType(dtm);
				case EnumTypeInfoModel.ID_STRING:
					return (Structure) EnumTypeInfoModel.getDataType(dtm);
				case FunctionTypeInfoModel.ID_STRING:
					return (Structure) FunctionTypeInfoModel.getDataType(dtm);
				case FundamentalTypeInfoModel.ID_STRING:
					return (Structure) FundamentalTypeInfoModel.getDataType(dtm);
				case IosFailTypeInfoModel.ID_STRING:
					return (Structure) IosFailTypeInfoModel.getDataType(dtm);
				case PBaseTypeInfoModel.ID_STRING:
					return (Structure) PBaseTypeInfoModel.getDataType(dtm);
				case PointerToMemberTypeInfoModel.ID_STRING:
					return (Structure) PointerToMemberTypeInfoModel.getDataType(dtm);
				case PointerTypeInfoModel.ID_STRING:
					return (Structure) PointerTypeInfoModel.getDataType(dtm);
				case SiClassTypeInfoModel.ID_STRING:
					return (Structure) SiClassTypeInfoModel.getDataType(dtm);
				case TypeInfoModel.ID_STRING:
					return (Structure) TypeInfoModel.getDataType(dtm);
				case VmiClassTypeInfoModel.ID_STRING:
					return (Structure) VmiClassTypeInfoModel.getDataType(dtm);
				default:
					throw new AssertException("Unknown type_info derivative "+getTypeName());
			}
		}
		return builder.getDataType();
	}

	@Override
	public GnuVtable getVtable() {
		if (vtable == null) {
			return Vtable.NO_VTABLE;
		}
		return vtable;
	}

	@Override
	public GnuVtable findVtable(TaskMonitor monitor) throws CancelledException {
		if (vtable != null) {
			return vtable;
		}
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(VtableModel.SYMBOL_NAME, getGhidraClass())) {
			GnuVtable tmpVtable = (GnuVtable) manager.getVtable(symbol.getAddress());
			if (Vtable.isValid(tmpVtable)) {
				vtable = tmpVtable;
				return vtable;
			}
			tmpVtable =
				VtableModel.getVtable(program, symbol.getAddress(), this);
			if (Vtable.isValid(tmpVtable)) {
				vtable = tmpVtable;
				return vtable;
			}
			BookmarkManager man = program.getBookmarkManager();
			man.setBookmark(
				symbol.getAddress(), BookmarkType.ERROR, null, "Vtable Validation Failed");
			String msg = String.format(
				"Symbol %s at %s is a valid vtable symbol but the data validation check failed",
				symbol.getName(), symbol.getAddress());
			Msg.warn(this, msg);
		}
		vtable = (GnuVtable) ClassTypeInfoUtils.findVtable(program, address, monitor);
		return vtable;
	}

	@Override
	public final boolean isAbstract() {
		return CppClassAnalyzerUtils.isAbstract(this, PURE_VIRTUAL_FUNCTION_NAME);
	}

	@Override
	public GhidraClass getGhidraClass() {
		if (!(namespace instanceof GhidraClass)) {
			Integer id = null;
			boolean success = false;
			try {
				if (program.getCurrentTransactionInfo() == null) {
					id = program.startTransaction("creating GhidraClass for "+getName());
				}
				if (namespace.getSymbol().isDeleted()) {
					namespace = TypeInfoUtils.getNamespaceFromTypeName(program, typeName);
					namespace = NamespaceUtils.convertNamespaceToClass(namespace);
				} else {
					namespace = NamespaceUtils.convertNamespaceToClass(namespace);
				}
				success = true;
			} catch (InvalidInputException e) {
				Msg.error(this, e);
				return null;
			} finally {
				if (id != null) {
					program.endTransaction(id, success);
				}
			}
		} return (GhidraClass) namespace;
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		return Collections.emptySet();
	}

	@Override
	public SymbolPath getSymbolPath() {
		return new SymbolPath(getGhidraClass().getSymbol());
	}

}
