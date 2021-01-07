package cppclassanalyzer.data.manager;

import java.io.IOException;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.caches.ArchivedRttiCachePair;
import cppclassanalyzer.data.manager.recordmanagers.ArchiveRttiRecordManager;
import cppclassanalyzer.data.manager.tables.ArchivedRttiTablePair;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.GnuClassTypeInfoDB;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;

import ghidra.program.database.DatabaseObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import cppclassanalyzer.database.record.ArchivedClassTypeInfoRecord;
import cppclassanalyzer.database.record.ArchivedGnuVtableRecord;
import cppclassanalyzer.database.schema.fields.ArchivedClassTypeInfoSchemaFields;
import cppclassanalyzer.database.schema.fields.ArchivedGnuVtableSchemaFields;
import cppclassanalyzer.database.utils.TransactionHandler;
import db.Field;
import db.StringField;

abstract class ArchiveRttiRecordWorker extends
		AbstractRttiRecordWorker<ArchivedClassTypeInfo, ArchivedGnuVtable,
			ArchivedClassTypeInfoRecord, ArchivedGnuVtableRecord, ArchivedRttiTablePair>
		implements ArchiveRttiRecordManager {

	private static final String MANGLED_TYPEINFO_PREFIX = "_ZTI";

	private final ClassTypeInfoManager manager;

	ArchiveRttiRecordWorker(ClassTypeInfoManager manager, ArchivedRttiTablePair tables,
			ArchivedRttiCachePair caches, TransactionHandler handler) {
		super(tables, caches, handler);
		this.manager = manager;
	}

	@Override
	public ClassTypeInfoManager getManager() {
		return manager;
	}

	@Override
	long getTypeKey(ClassTypeInfo type) {
		if (type instanceof ArchivedClassTypeInfo) {
			return ((ArchivedClassTypeInfo) type).getKey();
		}
		return getTypeKey(TypeInfoUtils.getSymbolName(type));
	}

	@Override
	long getVtableKey(Vtable vtable) {
		return getVtableKey(VtableUtils.getSymbolName(vtable));
	}

	@Override
	ArchivedClassTypeInfo buildType(ArchivedClassTypeInfoRecord record) {
		return new ArchivedClassTypeInfo(this, record);
	}

	@Override
	ArchivedClassTypeInfo buildType(ClassTypeInfo type, ArchivedClassTypeInfoRecord record) {
		if (type instanceof GnuClassTypeInfoDB) {
			return new ArchivedClassTypeInfo(this, (GnuClassTypeInfoDB) type, record);
		}
		return null;
	}

	@Override
	public void dbError(IOException e) {
		Msg.showError(this, null, "IO ERROR", e.getMessage(), e);
	}

	@Override
	final ArchivedGnuVtable buildVtable(ArchivedGnuVtableRecord record) {
		return new ArchivedGnuVtable(this, record);
	}

	@Override
	final ArchivedGnuVtable buildVtable(Vtable vtable, ArchivedGnuVtableRecord record) {
		return new ArchivedGnuVtable(this, (GnuVtable) vtable, record);
	}

	public final long getTypeKey(String symbolName) {
		try {
			StringField field = new StringField(symbolName);
			Field[] results = getTables().getTypeTable().findRecords(
				field, ArchivedClassTypeInfoSchemaFields.MANGLED_SYMBOL.ordinal());
			if (results.length == 1) {
				return results[0].getLongValue();
			}
		} catch (IOException e) {
			dbError(e);
		}
		return INVALID_KEY;
	}

	public final long getVtableKey(String symbolName) {
		try {
			StringField field = new StringField(symbolName);
			Field[] results = getTables().getVtableTable().findRecords(
				field, ArchivedGnuVtableSchemaFields.MANGLED_SYMBOL.ordinal());
			if (results.length == 1) {
				return results[0].getLongValue();
			}
		} catch (IOException e) {
			dbError(e);
		}
		return INVALID_KEY;
	}

	ArchivedClassTypeInfo getType(GhidraClass gc) throws UnresolvedClassTypeInfoException {
		Program program = gc.getSymbol().getProgram();
		SymbolTable table = program.getSymbolTable();
		return table.getSymbols(TypeInfo.TYPENAME_SYMBOL_NAME, gc)
			.stream()
			.findFirst()
			.map(Symbol::getAddress)
			.map(a -> TypeInfoUtils.getTypeName(program, a))
			.map(this::getType)
			.orElseGet(() -> {
				return null;
			});
	}

	ArchivedClassTypeInfo getType(Function fun) throws UnresolvedClassTypeInfoException {
		Namespace ns = fun.getParentNamespace();
		if (ns instanceof GhidraClass) {
			return getType((GhidraClass) ns);
		}
		return null;
	}

	ArchivedClassTypeInfo getType(String name, Namespace namespace)
			throws UnresolvedClassTypeInfoException {
		Program program = namespace.getSymbol().getProgram();
		SymbolTable table = program.getSymbolTable();
		Symbol s = table.getClassSymbol(name, namespace);
		if (s != null) {
			return getType((GhidraClass) s.getObject());
		}
		return null;
	}

	ArchivedClassTypeInfo getType(String symbolName) throws UnresolvedClassTypeInfoException {
		if (symbolName.isBlank() || !symbolName.startsWith(MANGLED_TYPEINFO_PREFIX)) {
			return null;
		}
		try {
			db.Field f = new StringField(symbolName);
			Field[] keys = getTables().getTypeTable().findRecords(
				f, ArchivedClassTypeInfoSchemaFields.MANGLED_SYMBOL.ordinal());
			if (keys.length == 1) {
				return getType(keys[0].getLongValue());
			}
		} catch (IOException e) {
			dbError(e);
		}
		return null;
	}
	
	DatabaseObject getArchivedData(String symbolName) {
		long key = getTypeKey(symbolName);
		if (key != INVALID_KEY) {
			return getType(key);
		}
		key = getVtableKey(symbolName);
		if (key != INVALID_KEY) {
			return getVtable(key);
		}
		return null;
	}

}
