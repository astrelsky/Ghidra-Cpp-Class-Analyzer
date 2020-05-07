package ghidra.program.database.data.rtti.typeinfo;

import java.util.*;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.ClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.SiClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;

import db.*;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

public abstract class AbstractClassTypeInfoDB extends DatabaseObject implements ClassTypeInfo {

	private static final int VERSION = 0;
	public static final String CLASS_TYPEINFO_TABLE_NAME = "ClassTypeInfo Table";

	private static final List<Class<? extends ClassTypeInfo>> CLASS_IDS = List.of(
		ClassTypeInfoModel.class,
		SiClassTypeInfoModel.class,
		VmiClassTypeInfoModel.class,
		RttiModelWrapper.class
	);

	public static enum SchemaOrdinals {
		TYPENAME,
		TYPEINFO_ID,
		ADDRESS,
		DATATYPE_ID,
		VTABLE_SEARCHED,
		VTABLE_KEY,
		MODEL_DATA
	};

	public static final int[] INDEXED_COLUMNS = new int[] {
		SchemaOrdinals.ADDRESS.ordinal()
	};

	public static final Schema SCHEMA =
		new Schema(
			VERSION,
			"Key",
			new Class[] {
				StringField.class,
				ByteField.class,
				LongField.class,
				LongField.class,
				BooleanField.class,
				LongField.class,
				BinaryField.class
			},
			new String[] {
				"type name",
				"typeinfo type id",
				"address",
				"datatype id",
				"vtable searched",
				"vtable key",
				"model specific data"
			}
	);

	protected final ClassTypeInfoManagerDB manager;
	protected Address address;
	protected final String typename;
	protected final GhidraClass gc;
	protected boolean vtableSearched;
	protected long vtableKey;
	private Structure struct;

	protected AbstractClassTypeInfoDB(ClassTypeInfoManagerDB manager,
			DBObjectCache<AbstractClassTypeInfoDB> cache, AbstractClassTypeInfoDB type,
			db.Record record) {
		super(cache, record.getKey());
		this.manager = manager;
		this.address = type.address;
		this.typename = type.typename;
		this.gc = type.gc;
		this.vtableSearched = type.vtableSearched;
		this.vtableKey = type.vtableKey;

		if (type.struct != null) {
			DataTypeManager dtm = getProgram().getDataTypeManager();
			this.struct = (Structure) type.struct.clone(dtm);
		}
		setRecord(type, record);
	}

	protected AbstractClassTypeInfoDB(ClassTypeInfoManagerDB manager,
		DBObjectCache<AbstractClassTypeInfoDB> cache, db.Record record) {
			super(cache, record.getKey());
			this.manager = manager;
			this.address = manager.decodeAddress(
				record.getLongValue(SchemaOrdinals.ADDRESS.ordinal()));
			this.typename = record.getString(SchemaOrdinals.TYPENAME.ordinal());
			this.vtableSearched = record.getBooleanValue(SchemaOrdinals.VTABLE_SEARCHED.ordinal());
			this.vtableKey = record.getLongValue(SchemaOrdinals.VTABLE_KEY.ordinal());
			this.gc = fetchGhidraClass();
			this.struct = fetchDataType(record);
	}

	protected AbstractClassTypeInfoDB(ClassTypeInfoManagerDB manager,
		DBObjectCache<AbstractClassTypeInfoDB> cache, ClassTypeInfo type, db.Record record) {
			super(cache, record.getKey());
			this.manager = manager;
			this.address = type.getAddress();
			this.typename = type.getTypeName();
			this.gc = type.getGhidraClass();
			setRecord(type, record);
	}

	protected AbstractClassTypeInfoDB(ClassTypeInfoManagerDB manager,
		DBObjectCache<AbstractClassTypeInfoDB> cache, ArchivedClassTypeInfo type,
		db.Record record) {
			super(cache, record.getKey());
			Program program = manager.getProgram();
			this.manager = manager;
			this.address = type.getAddress(program);
			this.typename = type.getTypeName();
			this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(program, typename);
			ArchivedGnuVtable vtable = type.getArchivedVtable();
			if (vtable == null) {
				this.vtableKey = AddressMap.INVALID_ADDRESS_KEY;
			} else {
				this.vtableKey = manager.resolve(vtable).getKey();
			}
			DataTypeManager dtm = program.getDataTypeManager();
			this.struct = (Structure) dtm.resolve(type.getDataType(), REPLACE_HANDLER);
			dtm.resolve(type.getSuperDataType(), REPLACE_HANDLER);
			record.setString(SchemaOrdinals.TYPENAME.ordinal(), typename);
			record.setLongValue(
				SchemaOrdinals.ADDRESS.ordinal(), manager.encodeAddress(address));
			manager.updateRecord(record);
			record.setByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal(), type.getClassId());
			record.setLongValue(
				SchemaOrdinals.DATATYPE_ID.ordinal(), struct.getUniversalID().getValue());
			this.vtableSearched = true;
			record.setBooleanValue(SchemaOrdinals.VTABLE_SEARCHED.ordinal(), vtableSearched);
			record.setLongValue(SchemaOrdinals.VTABLE_KEY.ordinal(), vtableKey);
			manager.updateRecord(record);
	}

	private void setRecord(ClassTypeInfo type, db.Record record) {
		record.setString(SchemaOrdinals.TYPENAME.ordinal(), type.getTypeName());
		record.setByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal(), getClassId(type));
		record.setLongValue(
			SchemaOrdinals.ADDRESS.ordinal(), manager.encodeAddress(type.getAddress()));
		record.setLongValue(
			SchemaOrdinals.DATATYPE_ID.ordinal(), AddressMap.INVALID_ADDRESS_KEY);
		Vtable vtable = type.getVtable();
		if (Vtable.isValid(vtable)) {
			this.vtableSearched = true;
			this.vtableKey = manager.getVtableKey(vtable.getAddress());
		} else {
			this.vtableSearched = false;
			this.vtableKey = -1;
		}
		record.setBooleanValue(SchemaOrdinals.VTABLE_SEARCHED.ordinal(), vtableSearched);
		record.setLongValue(SchemaOrdinals.VTABLE_KEY.ordinal(), vtableKey);
		manager.updateRecord(record);
	}

	protected abstract Namespace buildNamespace();
	protected abstract long[] getBaseKeys();
	protected abstract int[] getOffsets();

	public Map<ClassTypeInfo, Integer> getBaseOffsets() {
		long[] baseKeys = getBaseKeys();
		int[] baseOffsets = getOffsets();
		Map<ClassTypeInfo, Integer> map = new HashMap<>(baseKeys.length);
		for (int i = 0; i < baseKeys.length; i++) {
			map.put(manager.getClass(baseKeys[i]), baseOffsets[i]);
		}
		return Collections.unmodifiableMap(map);
	}

	protected static byte[] getClassData(db.Record record) {
		byte[] result = record.getBinaryData(SchemaOrdinals.MODEL_DATA.ordinal());
		return result;
	}

	protected static String getIdentifier(byte id) {
		try {
			return (String) CLASS_IDS.get(id).getField("ID_STRING").get(null);
		} catch (NoSuchFieldException e) {
			return "";
		} catch (IllegalAccessException e2) {
			throw new AssertException(e2);
		}
	}

	private static byte getClassId(ClassTypeInfo type) {
		byte result = (byte) CLASS_IDS.indexOf(type.getClass());
		return result;
	}

	protected boolean getVtableSearched() {
		db.Record record = getRecord();
		return record.getBooleanValue(SchemaOrdinals.VTABLE_SEARCHED.ordinal());
	}

	protected void setVtableSearched() {
		vtableSearched = true;
		db.Record record = getRecord();
		record.setBooleanValue(SchemaOrdinals.VTABLE_SEARCHED.ordinal(), true);
		manager.updateRecord(record);
	}

	public static int getBaseCount(db.Record record) {
		byte b = record.getByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal());
		if (b <= CLASS_IDS.indexOf(VmiClassTypeInfoModel.class)) {
			return GnuClassTypeInfoDB.getBaseCount(record);
		}
		if (b == CLASS_IDS.indexOf(RttiModelWrapper.class)) {
			return WindowsClassTypeInfoDB.getBaseCount(record);
		}
		throw new AssertException("Ghidra-Cpp-Class-Analyzer: invalid database record");
	}

	private GhidraClass fetchGhidraClass() {
		SymbolTable table = getProgram().getSymbolTable();
		Symbol s = table.getPrimarySymbol(address);
		Namespace ns = null;
		if (s == null || !s.getName().equals("typeinfo")) {
			ns = buildNamespace();
		} else {
			ns = s.getParentNamespace();
		}
		if (!(ns instanceof GhidraClass)) {
			if (ns.isGlobal()) {
				throw new AssertException(
					"Ghidra-Cpp-Class-Analyzer: unexpected global namespace at "
					+address.toString());
			}
			try {
				ns = NamespaceUtils.convertNamespaceToClass(ns);
			} catch (InvalidInputException e) {
				String msg = String.format(
					"Ghidra-Cpp-Class-Analyzer: %s should be a valid GhidraClass",
					ns.getName(true));
				throw new AssertException(msg);
			}
		}
		return (GhidraClass) ns;
	}

	private Structure fetchDataType(db.Record record) {
		long id = record.getLongValue(SchemaOrdinals.DATATYPE_ID.ordinal());
		if (id != AddressMap.INVALID_ADDRESS_KEY) {
			DataType dt = getProgram().getDataTypeManager().findDataTypeForID(
				new UniversalID(id));
			if (dt instanceof Structure) {
				return (Structure) dt;
			}
		}
		return null;
	}

	public static long[] getBaseKeys(db.Record record) {
		byte id = record.getByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal());
		if (id <= CLASS_IDS.indexOf(VmiClassTypeInfoModel.class)) {
			return GnuClassTypeInfoDB.getBaseKeys(record);
		}
		if (id == CLASS_IDS.indexOf(RttiModelWrapper.class)) {
			return WindowsClassTypeInfoDB.getBaseKeys(record);
		}
		return new long[0];
	}

	protected static void updateKeys(long[] keys, LongIntHashtable keyMap) {
		try {
			for (int i = 0; i < keys.length; i++) {
				keys[i] = keyMap.get(keys[i]);
			}
		} catch (NoValueException e) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: Failed to remap keys", e);
		}
	}

	public static void updateRecord(db.Record record, LongIntHashtable keyMap) {
		byte id = record.getByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal());
		if (id <= CLASS_IDS.indexOf(VmiClassTypeInfoModel.class)) {
			GnuClassTypeInfoDB.updateRecord(record, keyMap);
		} else if (id == CLASS_IDS.indexOf(RttiModelWrapper.class)) {
			WindowsClassTypeInfoDB.updateRecord(record, keyMap);
		}
	}

	private static boolean isTypeInfoSymbol(Symbol s) {
		return s.getName().equals(SYMBOL_NAME);
	}

	private Symbol getSymbol() {
		SymbolTable table = getProgram().getSymbolTable();
		return Arrays.stream(table.getSymbols(getAddress()))
			.filter(AbstractClassTypeInfoDB::isTypeInfoSymbol)
			.findFirst()
			.orElseGet(this::createSymbol);
	}

	private Symbol createSymbol() {
		Namespace ns = TypeInfoUtils.getNamespaceFromTypeName(getProgram(), getTypeName());
		try {
			SymbolTable table = getProgram().getSymbolTable();
			return table.createLabel(getAddress(), SYMBOL_NAME, ns, SourceType.ANALYSIS);
		} catch (InvalidInputException e) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: ", e);
		}
	}

	byte getClassID() {
		return getRecord().getByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal());
	}

	long getAddressKey() {
		return manager.encodeAddress(address);
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof AbstractClassTypeInfoDB) {
			return getKey() == ((AbstractClassTypeInfoDB) o).getKey();
		}
		if (o instanceof ClassTypeInfo) {
			return getAddress().equals(((ClassTypeInfo) o).getAddress());
		}
		return false;
	}

	@Override
	public final int hashCode() {
		return getTypeName().hashCode();
	}

	@Override
	protected boolean refresh() {
		return false;
	}

	public Program getProgram() {
		return manager.getProgram();
	}

	@Override
	public String getName() {
		return getNamespace().getName();
	}

	@Override
	public Namespace getNamespace() {
		return getSymbol().getParentNamespace();
	}

	@Override
	public String getTypeName() {
		return typename;
	}

	protected db.Record getRecord() {
		db.Record record = manager.getClassRecord(key);
		if (record != null) {
			return record;
		}
		throw new AssertException(
			String.format("Ghidra-Cpp-Class-Analyzer: %s db record no longer exists",
			getName()));
	}

	@Override
	public String getIdentifier() {
		db.Record record = getRecord();
		byte b = record.getByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal());
		if (b < CLASS_IDS.size()) {
			try {
				return (String) CLASS_IDS.get(b).getDeclaredField("ID_STRING").get(null);
			} catch (NoSuchFieldException e) {
				// Identifiers are for GNU RTTI only
				return "";
			} catch (Exception e) {
				throw new AssertException("Ghidra-Cpp-Class-Analyzer: ", e);
			}
		}
		throw new AssertException(
			"Ghidra-Cpp-Class-Analyzer: db record contains illegal typeinfo id");
	}

	@Override
	public DataType getDataType() {
		db.Record record = getRecord();
		byte b = record.getByteValue(SchemaOrdinals.TYPEINFO_ID.ordinal());
		if (b <= CLASS_IDS.size()) {
			try {
				return (DataType) CLASS_IDS.get(b)
					.getDeclaredMethod("getDataType", DataTypeManager.class)
					.invoke(null, getProgram().getDataTypeManager());
			} catch (Exception e) {
				throw new AssertException("Ghidra-Cpp-Class-Analyzer: ", e);
			}
		}
		throw new AssertException(
			"Ghidra-Cpp-Class-Analyzer: db record contains illegal typeinfo id");
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public GhidraClass getGhidraClass() {
		return gc;
	}

	@Override
	public Vtable getVtable() {
		return manager.getVtable(vtableKey);
	}

	public void setVtable(Vtable vtable) {
		db.Record record = getRecord();
		if (vtable != Vtable.NO_VTABLE) {
			if (!(vtable instanceof DatabaseObject)) {
				vtable = manager.resolve(vtable);
			}
			vtableKey = ((DatabaseObject) vtable).getKey();
		} else {
			vtableKey = -1;
		}
		record.setLongValue(SchemaOrdinals.VTABLE_KEY.ordinal(), vtableKey);
		manager.updateRecord(record);
	}

	@Override
	public Structure getClassDataType() {
		db.Record record = getRecord();
		if (struct != null) {
			long dtKey = record.getLongValue(SchemaOrdinals.DATATYPE_ID.ordinal());
			if (dtKey == AddressMap.INVALID_ADDRESS_KEY) {
				record.setLongValue(
					SchemaOrdinals.DATATYPE_ID.ordinal(), struct.getUniversalID().getValue());
				manager.updateRecord(record);
			}
			return struct;
		}
		GccCppClassBuilder builder = new GccCppClassBuilder(this);
		struct = builder.getDataType();
		record.setLongValue(
			SchemaOrdinals.DATATYPE_ID.ordinal(), struct.getUniversalID().getValue());
		manager.updateRecord(record);
		return struct;
	}

	@Override
	public String getUniqueTypeName() {
		StringBuilder builder = new StringBuilder(getTypeName());
		for (ClassTypeInfo parent : getParentModels()) {
			builder.append(parent.getTypeName());
		}
		return builder.toString();
	}

	@Override
	public boolean isAbstract() {
		return ClassTypeInfoUtils.isAbstract(this);
	}

	@Override
	public String toString() {
		return getName();
	}

}