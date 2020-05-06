package ghidra.program.database.data.rtti.vtable;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.GnuVtable.VtablePrefix;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.DataBaseUtils;
import ghidra.program.database.data.rtti.ArchiveClassTypeInfoManager.RecordManager;
import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UniversalID;

import db.*;

public class ArchivedGnuVtable extends DatabaseObject {

	private static final int VERSION = 0;
	public static final String TABLE_NAME = "Vtable Archive Table";

	public static enum SchemaOrdinals {
		/** Address within the external program */
		ADDRESS,
		/** Must be the mangled symbol */
		SYMBOL_NAME,
		TYPE_KEY,
		DATA
	};

	public static final int[] INDEXED_COLUMNS = new int[] {
		SchemaOrdinals.SYMBOL_NAME.ordinal()
	};

	public static final Schema SCHEMA =
		new Schema(
			VERSION,
			"Key",
			new Class[] {
				LongField.class,
				StringField.class,
				LongField.class,
				BinaryField.class
			},
			new String[] {
				"address",
				"symbol name",
				"type key",
				"vtable data"
			}
	);

	private final RecordManager manager;
	private final long address;
	private final ArchivedClassTypeInfo type;
	private final String symbolName;
	private final ArchivedVtablePrefix[] prefixes;

	public ArchivedGnuVtable(RecordManager manager,
			DBObjectCache<ArchivedGnuVtable> cache, GnuVtable vtable,
			db.Record record) {
		super(cache, record.getKey());
		this.manager = manager;
		this.symbolName = VtableUtils.getSymbolName(vtable);
		Program program = VtableUtils.getProgram(vtable);
		this.address = program.getAddressMap().getKey(vtable.getAddress(), true);
		this.type = manager.getManager().resolve(vtable.getTypeInfo());
		this.prefixes = vtable.getPrefixes()
			.stream()
			.map(ArchivedVtablePrefix::new)
			.toArray(ArchivedVtablePrefix[]::new);
		record.setLongValue(SchemaOrdinals.ADDRESS.ordinal(), address);
		record.setString(SchemaOrdinals.SYMBOL_NAME.ordinal(), symbolName);
		record.setLongValue(SchemaOrdinals.TYPE_KEY.ordinal(), type.getKey());
		record.setBinaryData(SchemaOrdinals.DATA.ordinal(), getVtableData());
		manager.updateRecord(record);
	}

	public ArchivedGnuVtable(RecordManager manager,
			DBObjectCache<ArchivedGnuVtable> cache, db.Record record) {
		super(cache, record.getKey());
		this.manager = manager;
		ArchiveClassTypeInfoManager classManager = manager.getManager();
		this.address = record.getLongValue(SchemaOrdinals.ADDRESS.ordinal());
		this.symbolName = record.getString(SchemaOrdinals.SYMBOL_NAME.ordinal());
		this.type = classManager.getClass(
			record.getLongValue(SchemaOrdinals.TYPE_KEY.ordinal()));
		byte[] data = record.getBinaryData(SchemaOrdinals.DATA.ordinal());
		this.prefixes = getArray(data);
	}

	public static db.Record createRecord(long key) {
		return SCHEMA.createRecord(key);
	}

	private static FunctionDefinition[] toDefinition(Function[] table, DataTypeManager dtm) {
		return Arrays.stream(table)
					 .map(Function::getSignature)
					 .map(f -> new FunctionDefinitionDataType(f, dtm))
					 .toArray(FunctionDefinition[]::new);
	}

	public Address getAddress(Program program) {
		return program.getAddressMap().decodeAddress(address);
	}

	public static Function getFunction(Program program, FunctionDefinition def) {
		SymbolTable table = program.getSymbolTable();
		String name = def.getName();
		Symbol s = table.getExternalSymbol(name);
		if (s != null && s.getObject() instanceof Function) {
			return (Function) s.getObject();
		}
		throw new IllegalArgumentException(
			def.getPrototypeString()+" does not exist in "+program.getName());
	}

	static Function[] getFunctions(Program program, ArchivedVtablePrefix prefix) {
		return Arrays.stream(prefix.getDefinitions())
			.map(f -> getFunction(program, f))
			.toArray(Function[]::new);
	}

	public FunctionDefinition[][] getFunctionDefinitions() {
		return Arrays.stream(prefixes)
			.map(ArchivedVtablePrefix::getDefinitions)
			.toArray(FunctionDefinition[][]::new);
	}

	@Override
	protected boolean refresh() {
		return false;
	}

	public static FunctionDefinition[][] getFunctionDefinitions(Function[][] table,
		DataTypeManager dtm) {
			return Arrays.stream(table)
				.map(t -> toDefinition(t, dtm))
				.toArray(FunctionDefinition[][]::new);
	}

	public ArchivedClassTypeInfo getClassTypeInfo() {
		return type;
	}

	public String getSymbolName() {
		return symbolName;
	}

	private ArchivedVtablePrefix[] getArray(byte[] data) {
		ByteBuffer buf = ByteBuffer.wrap(data);
		PrefixGenerator generator = new PrefixGenerator(buf);
		return Stream.generate(generator)
			.limit(generator.size)
			.toArray(ArchivedVtablePrefix[]::new);
	}

	private byte[] getVtableData() {
		int size = Arrays.stream(prefixes)
			.mapToInt(ArchivedVtablePrefix::getSize)
			.sum() + Integer.BYTES;
		ByteBuffer buf = ByteBuffer.allocate(size);
		buf.putInt(prefixes.length);
		for (ArchivedVtablePrefix prefix : prefixes) {
			buf.put(prefix.toBytes());
		}
		return buf.array();
	}

	ArchivedVtablePrefix[] getPrefixes() {
		return prefixes;
	}

	class ArchivedVtablePrefix {

		final long[] offsets;
		final long[] functions;

		ArchivedVtablePrefix(VtablePrefix prefix) {
			this.offsets = prefix.getOffsets()
				.stream()
				.mapToLong(Long::longValue)
				.toArray();
			this.functions = prefix.getFunctionTable()
				.stream()
				.map(Function::getSignature)
				.map(f -> new FunctionDefinitionDataType(f, manager.getManager()))
				.map(FunctionDefinition::getUniversalID)
				.mapToLong(UniversalID::getValue)
				.toArray();
		}

		ArchivedVtablePrefix(ByteBuffer buf) {
			this.offsets = DataBaseUtils.getLongArray(buf);
			this.functions = DataBaseUtils.getLongArray(buf);
		}

		int getSize() {
			return Integer.BYTES * 2
				+ Long.BYTES * offsets.length
				+ Long.BYTES * functions.length;
		}

		byte[] toBytes() {
			ByteBuffer buf = ByteBuffer.allocate(getSize());
			DataBaseUtils.putLongArray(buf, offsets);
			DataBaseUtils.putLongArray(buf, functions);
			return buf.array();
		}

		FunctionDefinition[] getDefinitions() {
			DataTypeManager dtm = manager.getManager();
			return Arrays.stream(functions)
				.mapToObj(UniversalID::new)
				.map(dtm::findDataTypeForID)
				.map(FunctionDefinition.class::cast)
				.toArray(FunctionDefinition[]::new);
		}
	}

	private class PrefixGenerator implements Supplier<ArchivedVtablePrefix> {

		private final int size;
		private final ByteBuffer buf;

		PrefixGenerator(ByteBuffer buf) {
			this.size = buf.getInt();
			this.buf = buf;
		}

		@Override
		public ArchivedVtablePrefix get() {
			return new ArchivedVtablePrefix(buf);
		}

	}
}