package cppclassanalyzer.data.typeinfo;

import java.util.*;

import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.ClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.SiClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.program.database.DatabaseObject;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import cppclassanalyzer.data.vtable.AbstractVtableDB;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NoValueException;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;

import static cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields.*;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

public abstract class AbstractClassTypeInfoDB extends ClassTypeInfoDB {

	public static final String CLASS_TYPEINFO_TABLE_NAME = "ClassTypeInfo Table";

	protected final ProgramRttiRecordManager manager;
	private final Address address;
	private final String typename;
	private boolean vtableSearched;
	private long vtableKey;
	private Structure struct;

	protected AbstractClassTypeInfoDB(ProgramRttiRecordManager manager,
			ClassTypeInfoRecord record) {
		super(manager, record.getKey());
		this.manager = manager;
		this.address = getManager().decodeAddress(record.getLongValue(ADDRESS));
		this.typename = record.getStringValue(TYPENAME);
		this.vtableSearched = record.getBooleanValue(VTABLE_SEARCHED);
		this.vtableKey = record.getLongValue(VTABLE_KEY);
		this.struct = fetchDataType(record);
	}

	protected AbstractClassTypeInfoDB(ProgramRttiRecordManager manager, ClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(manager, record.getKey());
		this.manager = manager;
		this.address = type.getAddress();
		this.typename = type.getTypeName();
		setRecord(type, record);
	}

	protected AbstractClassTypeInfoDB(ProgramRttiRecordManager manager, ArchivedClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(manager, record.getKey());
		this.manager = manager;
		Program program = getProgram();
		this.address = type.getAddress(program);
		this.typename = type.getTypeName();
		ArchivedGnuVtable archivedVtable = type.getArchivedVtable();
		if (archivedVtable == null) {
			this.vtableKey = INVALID_KEY;
		} else {
			Vtable vtable = getManager().resolve(archivedVtable);
			if (vtable instanceof DatabaseObject) {
				this.vtableKey = ((DatabaseObject) vtable).getKey();
			} else {
				this.vtableKey = INVALID_KEY;
			}
		}
		DataTypeManager dtm = program.getDataTypeManager();
		this.struct = (Structure) dtm.resolve(type.getDataType(), REPLACE_HANDLER);
		dtm.resolve(type.getSuperDataType(), REPLACE_HANDLER);
		record.setStringValue(TYPENAME, typename);
		record.setLongValue(ADDRESS, getManager().encodeAddress(address));
		manager.updateRecord(record);
		record.setByteValue(TYPEINFO_ID, type.getClassId());
		record.setLongValue(DATATYPE_ID, struct.getUniversalID().getValue());
		this.vtableSearched = true;
		record.setBooleanValue(VTABLE_SEARCHED, vtableSearched);
		record.setLongValue(VTABLE_KEY, vtableKey);
		manager.updateRecord(record);
	}

	private void setRecord(ClassTypeInfo type, ClassTypeInfoRecord record) {
		record.setStringValue(TYPENAME, type.getTypeName());
		record.setByteValue(TYPEINFO_ID, TypeId.encode(type));
		record.setLongValue(ADDRESS, getManager().encodeAddress(type.getAddress()));
		record.setLongValue(DATATYPE_ID, INVALID_KEY);
		Vtable vtable = type.getVtable();
		if (Vtable.isValid(vtable)) {
			setVtableSearched();
			setVtable(vtable);
		} else {
			this.vtableSearched = false;
			this.vtableKey = -1;
		}
		record.setBooleanValue(VTABLE_SEARCHED, vtableSearched);
		record.setLongValue(VTABLE_KEY, vtableKey);
		manager.updateRecord(record);
	}

	protected abstract long[] getBaseKeys();
	protected abstract int[] getOffsets();
	protected abstract String getPureVirtualFunctionName();
	protected abstract AbstractCppClassBuilder getClassBuilder();
	protected abstract void fillOffsets(ClassTypeInfoRecord record);

	@Override
	public ClassTypeInfoManagerDB getManager() {
		return (ClassTypeInfoManagerDB) manager.getManager();
	}

	@Override
	public Map<ClassTypeInfo, Integer> getBaseOffsets() {
		long[] baseKeys = getBaseKeys();
		int[] baseOffsets = getOffsets();
		if (baseKeys.length > 0 && baseOffsets.length == 0) {
			String msg = "Invalid model data for "+getGhidraClass().getName(true);
			Msg.warn(this, msg);
			return Collections.emptyMap();
		}
		Map<ClassTypeInfoDB, Integer> map = new HashMap<>(baseKeys.length);
		for (int i = 0; i < baseKeys.length; i++) {
			map.put(manager.getType(baseKeys[i]), baseOffsets[i]);
		}
		return Collections.unmodifiableMap(map);
	}

	protected static byte[] getClassData(ClassTypeInfoRecord record) {
		return record.getBinaryData(MODEL_DATA);
	}

	protected static String getIdentifier(byte id) {
		return TypeId.decode(id).getIdentifier();
	}

	protected boolean getVtableSearched() {
		ClassTypeInfoRecord record = getRecord();
		return record.getBooleanValue(VTABLE_SEARCHED);
	}

	public static int getBaseCount(ClassTypeInfoRecord record) {
		byte id = record.getByteValue(TYPEINFO_ID);
		switch (TypeId.decode(id)) {
			case CLASS:
			case SI_CLASS:
			case VMI_CLASS:
				return GnuClassTypeInfoDB.getBaseCount(record);
			case RTTI_MODEL_WRAPPER:
				return WindowsClassTypeInfoDB.getBaseCount(record);
			default:
				// impossible but javac complains for some reason
				throw new AssertException("Ghidra-Cpp-Class-Analyzer: invalid database record");
		}
	}

	private Structure fetchDataType(ClassTypeInfoRecord record) {
		long id = record.getLongValue(DATATYPE_ID);
		if (id != INVALID_KEY) {
			DataType dt = getProgram().getDataTypeManager().findDataTypeForID(
				new UniversalID(id));
			if (dt instanceof Structure) {
				return (Structure) dt;
			}
		}
		return null;
	}

	public static long[] getBaseKeys(ClassTypeInfoRecord record) {
		byte id = record.getByteValue(TYPEINFO_ID);
		switch (TypeId.decode(id)) {
			case CLASS:
			case SI_CLASS:
			case VMI_CLASS:
				return GnuClassTypeInfoDB.getBaseKeys(record);
			case RTTI_MODEL_WRAPPER:
				return WindowsClassTypeInfoDB.getBaseKeys(record);
			default:
				// impossible but javac complains for some reason
				throw new AssertException("Ghidra-Cpp-Class-Analyzer: invalid database record");
		}
	}

	public TypeId getTypeId() {
		return TypeId.decode(getRecord().getByteValue(TYPEINFO_ID));
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

	public static void updateRecord(ClassTypeInfoRecord record, LongIntHashtable keyMap) {
		byte id = record.getByteValue(TYPEINFO_ID);
		switch (TypeId.decode(id)) {
			case CLASS:
			case SI_CLASS:
			case VMI_CLASS:
				GnuClassTypeInfoDB.updateRecord(record, keyMap);
				break;
			case RTTI_MODEL_WRAPPER:
				WindowsClassTypeInfoDB.updateRecord(record, keyMap);
				break;
		}
	}

	@Override
	public boolean equals(Object o) {
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
		return refresh(getRecord());
	}

	@Override
	protected boolean refresh(db.Record record) {
		return refresh(new ClassTypeInfoRecord(record));
	}

	protected boolean isVtableSearched() {
		return vtableSearched;
	}

	protected void setVtableSearched() {
		this.vtableSearched = true;
		ClassTypeInfoRecord record = getRecord();
		record.setBooleanValue(VTABLE_SEARCHED, true);
		manager.updateRecord(record);
	}

	protected boolean refresh(ClassTypeInfoRecord record) {
		if (record == null) {
			return false;
		}
		Address addr = getManager().decodeAddress(record.getLongValue(ADDRESS));
		if (address.equals(addr)) {
			vtableSearched = record.getBooleanValue(VTABLE_SEARCHED);
			vtableKey = record.getLongValue(VTABLE_KEY);
			struct = fetchDataType(record);
			return true;
		}
		return false;
	}

	public Program getProgram() {
		return getManager().getProgram();
	}

	@Override
	public String getName() {
		return getNamespace().getName();
	}

	@Override
	public final GhidraClass getGhidraClass() {
		return (GhidraClass) getNamespace();
	}

	@Override
	public String getTypeName() {
		return typename;
	}

	protected ClassTypeInfoRecord getRecord() {
		ClassTypeInfoRecord record = manager.getTypeRecord(key);
		if (record != null) {
			return record;
		}
		throw new AssertException(
			String.format("Ghidra-Cpp-Class-Analyzer: %s db record no longer exists",
			getName()));
	}

	@Override
	public String getIdentifier() {
		ClassTypeInfoRecord record = getRecord();
		byte id = record.getByteValue(TYPEINFO_ID);
		return TypeId.decode(id).getIdentifier();
	}

	@Override
	public DataType getDataType() {
		ClassTypeInfoRecord record = getRecord();
		byte id = record.getByteValue(TYPEINFO_ID);
		try {
			return (DataType) TypeId.decode(id).clazz
				.getDeclaredMethod("getDataType", DataTypeManager.class)
				.invoke(null, getProgram().getDataTypeManager());
		} catch (Exception e) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: ", e);
		}
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public Vtable getVtable() {
		Vtable vtable = manager.getVtable(vtableKey);
		if (vtable == null) {
			return Vtable.NO_VTABLE;
		}
		return vtable;
	}

	public void setVtable(Vtable vtable) {
		ClassTypeInfoRecord record = getRecord();
		if (vtable != Vtable.NO_VTABLE) {
			if (!(vtable instanceof DatabaseObject)) {
				vtable = manager.resolve(vtable);
				((AbstractVtableDB) vtable).setClassKey(key);
			}
			vtableKey = ((DatabaseObject) vtable).getKey();
		} else {
			vtableKey = -1;
		}
		record.setLongValue(VTABLE_KEY, vtableKey);
		fillOffsets(record);
		manager.updateRecord(record);
	}

	@Override
	public Structure getClassDataType() {
		ClassTypeInfoRecord record = getRecord();
		if (struct != null) {
			if (!ClassTypeInfoUtils.isPlaceholder(struct)) {
				long dtKey = record.getLongValue(DATATYPE_ID);
				if (dtKey == INVALID_KEY) {
					record.setLongValue(DATATYPE_ID, struct.getUniversalID().getValue());
					manager.updateRecord(record);
				}
				return struct;
			}
		}
		AbstractCppClassBuilder builder = getClassBuilder();
		struct = builder.getDataType();
		record.setLongValue(DATATYPE_ID, struct.getUniversalID().getValue());
		manager.updateRecord(record);
		return struct;
	}

	public long getClassDataTypeId() {
		ClassTypeInfoRecord record = getRecord();
		return record.getLongValue(DATATYPE_ID);
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
		if (vtableSearched && Vtable.isValid(getVtable())) {
			String virtualFunctionName = getPureVirtualFunctionName();
			return Arrays.stream(getVtable().getFunctionTables())
				.flatMap(Arrays::stream)
				.filter(Objects::nonNull)
				.map(Function::getName)
				.anyMatch(virtualFunctionName::equals);
		}
		return false;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public final boolean isModifiable() {
		return true;
	}

	public static enum TypeId {
		CLASS(ClassTypeInfoModel.class),
		SI_CLASS(SiClassTypeInfoModel.class),
		VMI_CLASS(VmiClassTypeInfoModel.class),
		RTTI_MODEL_WRAPPER(RttiModelWrapper.class);

		private final Class<? extends ClassTypeInfo> clazz;

		private TypeId(Class<? extends ClassTypeInfo> clazz) {
			this.clazz = clazz;
		}

		public String getIdentifier() {
			switch (this) {
				case CLASS:
					return ClassTypeInfoModel.ID_STRING;
				case SI_CLASS:
					return SiClassTypeInfoModel.ID_STRING;
				case VMI_CLASS:
					return VmiClassTypeInfoModel.ID_STRING;
				default:
					return "";
			}
		}

		private static TypeId decode(byte b) {
			return values()[b];
		}

		private static byte encode(ClassTypeInfo type) {
			return (byte) Arrays.stream(values())
				.filter(v -> v.isEquivalent(type))
				.mapToInt(TypeId::ordinal)
				.findFirst()
				.orElseThrow();
		}

		private boolean isEquivalent(ClassTypeInfo type) {
			return clazz == type.getClass();
		}

		protected byte encode() {
			return (byte) ordinal();
		}
	}

}