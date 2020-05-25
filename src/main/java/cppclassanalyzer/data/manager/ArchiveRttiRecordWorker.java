package cppclassanalyzer.data.manager;

import java.io.IOException;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import cppclassanalyzer.data.manager.caches.ArchivedRttiCachePair;
import cppclassanalyzer.data.manager.recordmanagers.ArchiveRttiRecordManager;
import cppclassanalyzer.data.manager.tables.ArchivedRttiTablePair;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.GnuClassTypeInfoDB;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;
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
import db.StringField;

abstract class ArchiveRttiRecordWorker extends
		AbstractRttiRecordWorker<ArchivedClassTypeInfo, ArchivedGnuVtable,
			ArchivedClassTypeInfoRecord, ArchivedGnuVtableRecord, ArchivedRttiTablePair>
		implements ArchiveRttiRecordManager {

	private static final String MANGLED_TYPEINFO_PREFIX = "_ZTI";

	private final FileArchiveClassTypeInfoManager manager;

	ArchiveRttiRecordWorker(FileArchiveClassTypeInfoManager manager, ArchivedRttiTablePair tables,
			ArchivedRttiCachePair caches) {
		super(tables, caches);
		this.manager = manager;
	}

	@Override
	public FileArchiveClassTypeInfoManager getManager() {
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
		acquireLock();
		try {
			StringField field = new StringField(symbolName);
			long[] results = getTables().getTypeTable().findRecords(
				field, ArchivedClassTypeInfoSchemaFields.MANGLED_SYMBOL.ordinal());
			if (results.length == 1) {
				return results[0];
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			releaseLock();
		}
		return INVALID_KEY;
	}

	public final long getVtableKey(String symbolName) {
		acquireLock();
		try {
			StringField field = new StringField(symbolName);
			long[] results = getTables().getVtableTable().findRecords(
				field, ArchivedGnuVtableSchemaFields.MANGLED_SYMBOL.ordinal());
			if (results.length == 1) {
				return results[0];
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			releaseLock();
		}
		return INVALID_KEY;
	}

	ClassTypeInfoDB getType(GhidraClass gc) throws UnresolvedClassTypeInfoException {
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

	ClassTypeInfoDB getType(Function fun) throws UnresolvedClassTypeInfoException {
		Namespace ns = fun.getParentNamespace();
		if (ns instanceof GhidraClass) {
			return getType((GhidraClass) ns);
		}
		return null;
	}

	ClassTypeInfoDB getType(String name, Namespace namespace)
			throws UnresolvedClassTypeInfoException {
		Program program = namespace.getSymbol().getProgram();
		SymbolTable table = program.getSymbolTable();
		Symbol s = table.getClassSymbol(name, namespace);
		if (s != null && s.getClass() == GhidraClass.class) {
			return getType((GhidraClass) s.getObject());
		}
		return null;
	}

	ClassTypeInfoDB getType(String typeName) throws UnresolvedClassTypeInfoException {
		if (typeName.isBlank()) {
			return null;
		}
		if (typeName.startsWith(MANGLED_TYPEINFO_PREFIX)) {
			typeName = typeName.substring(MANGLED_TYPEINFO_PREFIX.length());
		}
		acquireLock();
		try {
			db.Field f = new StringField(typeName);
			long[] keys = getTables().getTypeTable().findRecords(
				f, ArchivedClassTypeInfoSchemaFields.TYPENAME.ordinal());
			if (keys.length == 1) {
				return getType(keys[0]);
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			releaseLock();
		}
		return null;
	}

}