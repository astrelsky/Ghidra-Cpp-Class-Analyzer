package cppclassanalyzer.data.vtable;

import static cppclassanalyzer.database.schema.fields.ArchivedGnuVtableSchemaFields.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.GnuVtable.VtablePrefix;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.program.database.DatabaseObject;

import cppclassanalyzer.data.manager.recordmanagers.ArchiveRttiRecordManager;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UniversalID;

import cppclassanalyzer.database.record.ArchivedGnuVtableRecord;

public class ArchivedGnuVtable extends DatabaseObject implements ArchivedVtable {

	private static final UniversalID BAD_ID = new UniversalID(-1);
	public static final String TABLE_NAME = "Vtable Archive Table";

	private final ArchiveRttiRecordManager manager;
	private final long address;
	private final ArchivedClassTypeInfo type;
	private final String symbolName;
	private final ArchivedVtablePrefix[] prefixes;

	@SuppressWarnings("removal")
	public ArchivedGnuVtable(ArchiveRttiRecordManager worker, GnuVtable vtable,
			ArchivedGnuVtableRecord record) {
		super(worker.getVtableCache(), record.getKey());
		this.manager = worker;
		this.symbolName = VtableUtils.getSymbolName(vtable);
		Program program = VtableUtils.getProgram(vtable);
		this.address = program.getAddressMap().getKey(vtable.getAddress(), true);
		this.type = (ArchivedClassTypeInfo) manager.getManager().resolve(vtable.getTypeInfo());
		this.prefixes = vtable.getPrefixes()
			.stream()
			.map(ArchivedVtablePrefix::new)
			.toArray(ArchivedVtablePrefix[]::new);
		record.setLongValue(ADDRESS, address);
		record.setStringValue(MANGLED_SYMBOL, symbolName);
		record.setLongValue(TYPE_KEY, type.getKey());
		record.setBinaryData(DATA, getVtableData());
		manager.updateRecord(record);
	}

	public ArchivedGnuVtable(ArchiveRttiRecordManager worker, ArchivedGnuVtableRecord record) {
		super(worker.getVtableCache(), record.getKey());
		this.manager = worker;
		this.address = record.getLongValue(ADDRESS);
		this.symbolName = record.getStringValue(MANGLED_SYMBOL);
		this.type = manager.getType(record.getLongValue(TYPE_KEY));
		byte[] data = record.getBinaryData(DATA);
		this.prefixes = getArray(data);
	}

	@Override
	protected boolean refresh() {
		return false;
	}

	@Override
	public ClassTypeInfo getTypeInfo() {
		return type;
	}

	@Override
	public FunctionDefinition[][] getFunctionDefinitions() {
		return Arrays.stream(prefixes)
			.map(ArchivedVtablePrefix::getDefinitions)
			.toArray(FunctionDefinition[][]::new);
	}

	@SuppressWarnings("removal")
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
				.map(Optional::ofNullable)
				.map(this::getFunctionId)
				.mapToLong(UniversalID::getValue)
				.toArray();
		}

		ArchivedVtablePrefix(ByteBuffer buf) {
			this.offsets = ArchivedGnuVtableRecord.getLongArray(buf);
			this.functions = ArchivedGnuVtableRecord.getLongArray(buf);
		}

		private UniversalID getFunctionId(Optional<Function> fun) {
			return fun.map(Function::getSignature)
			.map(this::resolve)
			.map(FunctionDefinition::getUniversalID)
			.orElse(BAD_ID);
		}

		private FunctionDefinition resolve(FunctionSignature sig) {
			DataTypeManager dtm = manager.getDataTypeManager();
			FunctionDefinition def = new FunctionDefinitionDataType(sig, dtm);
			return (FunctionDefinition) dtm.resolve(def, DataTypeConflictHandler.KEEP_HANDLER);
		}

		int getSize() {
			return Integer.BYTES * 2
				+ Long.BYTES * offsets.length
				+ Long.BYTES * functions.length;
		}

		byte[] toBytes() {
			ByteBuffer buf = ByteBuffer.allocate(getSize());
			ArchivedGnuVtableRecord.setLongArray(buf, offsets);
			ArchivedGnuVtableRecord.setLongArray(buf, functions);
			return buf.array();
		}

		FunctionDefinition[] getDefinitions() {
			DataTypeManager dtm = manager.getDataTypeManager();
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
