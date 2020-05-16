package ghidra.program.database.data.rtti.typeinfo;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;

import javax.help.UnsupportedOperationException;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.database.data.rtti.manager.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.manager.recordmanagers.ArchiveRttiRecordManager;
import ghidra.program.database.data.rtti.DataBaseUtils;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import db.*;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

public final class ArchivedClassTypeInfo extends ClassTypeInfoDB {

	private static final int VERSION = 0;
	public static final String TABLE_NAME = "ClassTypeInfo Archive Table";

	public static enum SchemaOrdinals {
		/** Name of the Program the type originated from */
		PROGRAM_NAME,
		TYPENAME,
		/** Address within the external program */
		ADDRESS,
		/** Must be the mangled symbol */
		SYMBOL_NAME,
		CLASS_ID,
		DATATYPE_ID,
		SUPER_DATATYPE_ID,
		VTABLE_KEY,
		BASE_KEYS,
		VIRTUAL_BASE_KEYS,
		BASE_OFFSETS
	};

	public static final int[] INDEXED_COLUMNS = new int[] {
		SchemaOrdinals.TYPENAME.ordinal(),
		SchemaOrdinals.SYMBOL_NAME.ordinal()
	};

	public static final Schema SCHEMA =
		new Schema(
			VERSION,
			"Key",
			new Class[] {
				StringField.class,
				StringField.class,
				LongField.class,
				StringField.class,
				ByteField.class,
				LongField.class,
				LongField.class,
				LongField.class,
				BinaryField.class,
				BinaryField.class,
				BinaryField.class
			},
			new String[] {
				"program name",
				"type name",
				"address",
				"symbol name",
				"class id",
				"datatype id",
				"super datatype id",
				"vtable key",
				"non virtual base keys",
				"virtual base keys",
				"base offsets"
			});

	private static final Set<String> PURE_VIRTUAL_FUNCTION_NAMES =
		Set.of("__cxa_pure_virtual", "_purecall");

	private final ArchiveRttiRecordManager manager;
	private final long address;
	private final String programName;
	private final String typeName;
	private final String symbolName;
	private final byte classId;
	private final Structure struct;
	private final Structure superStruct;
	private final ArchivedGnuVtable vtable;
	private final int[] baseOffsets;
	private final long[] baseKeys;
	private final long[] virtualKeys;
	private final Demangled demangled;

	public ArchivedClassTypeInfo(ArchiveRttiRecordManager manager, GnuClassTypeInfoDB type,
			db.Record record) {
		super(manager, record);
		this.manager = manager;
		DataTypeManager archiveDtm = (DataTypeManager) manager.getManager();
		this.address = type.getRecord()
			.getLongValue(AbstractClassTypeInfoDB.SchemaOrdinals.ADDRESS.ordinal());
		record.setLongValue(SchemaOrdinals.ADDRESS.ordinal(), address);
		this.programName = type.getProgram().getName();
		this.typeName = type.getTypeName();
		this.symbolName = TypeInfoUtils.getSymbolName(type);
		this.classId = type.getClassID();
		this.struct = (Structure) archiveDtm.resolve(type.getClassDataType(), KEEP_HANDLER);
		DataTypeManager dtm = struct.getDataTypeManager();
		DataType superDt = dtm.getDataType(getCategoryPath(), "super_" + struct.getName());
		if (superDt != null) {
			this.superStruct = (Structure) archiveDtm.resolve(superDt, KEEP_HANDLER);
		} else {
			this.superStruct = this.struct;
		}
		this.baseKeys = type.getNonVirtualBaseKeys();
		this.baseOffsets = type.getOffsets();
		this.virtualKeys = type.getVirtualBaseKeys();
		record.setString(SchemaOrdinals.PROGRAM_NAME.ordinal(), programName);
		record.setString(SchemaOrdinals.TYPENAME.ordinal(), typeName);
		record.setString(SchemaOrdinals.SYMBOL_NAME.ordinal(), symbolName);
		record.setByteValue(SchemaOrdinals.CLASS_ID.ordinal(), classId);
		record.setLongValue(
			SchemaOrdinals.DATATYPE_ID.ordinal(), struct.getUniversalID().getValue());
		record.setLongValue(
			SchemaOrdinals.SUPER_DATATYPE_ID.ordinal(), superStruct.getUniversalID().getValue());
		DataBaseUtils.putLongArray(
			record, baseKeys, SchemaOrdinals.BASE_KEYS.ordinal());
		DataBaseUtils.putLongArray(
			record, virtualKeys, SchemaOrdinals.VIRTUAL_BASE_KEYS.ordinal());
		DataBaseUtils.putIntArray(
			record, baseOffsets, SchemaOrdinals.BASE_OFFSETS.ordinal());

		// vtable must be done last to resolve symbol name
		if (Vtable.isValid(type.getVtable())) {
			// must update first or face infinite recursion
			manager.updateRecord(record);
			this.vtable = this.manager.resolve(type.getVtable());
			record.setLongValue(SchemaOrdinals.VTABLE_KEY.ordinal(), vtable.getKey());
		} else {
			this.vtable = null;
			record.setLongValue(SchemaOrdinals.VTABLE_KEY.ordinal(), -1);
		}
		manager.updateRecord(record);
		this.demangled = doDemangle(symbolName);
	}

	public ArchivedClassTypeInfo(ArchiveRttiRecordManager manager, db.Record record) {
		super(manager, record);
		this.manager = manager;
		DataTypeManager classManager = (DataTypeManager) manager.getManager();
		this.address = record.getLongValue(SchemaOrdinals.ADDRESS.ordinal());
		this.programName = record.getString(SchemaOrdinals.PROGRAM_NAME.ordinal());
		this.typeName = record.getString(SchemaOrdinals.TYPENAME.ordinal());
		this.symbolName = record.getString(SchemaOrdinals.SYMBOL_NAME.ordinal());
		this.classId = record.getByteValue(SchemaOrdinals.CLASS_ID.ordinal());
		UniversalID id = new UniversalID(
			record.getLongValue(SchemaOrdinals.DATATYPE_ID.ordinal()));
		this.struct = (Structure) classManager.findDataTypeForID(id);
		id = new UniversalID(
			record.getLongValue(SchemaOrdinals.SUPER_DATATYPE_ID.ordinal()));
		this.superStruct = (Structure) classManager.findDataTypeForID(id);
		long vtableKey = record.getLongValue(SchemaOrdinals.VTABLE_KEY.ordinal());
		if (vtableKey != -1) {
			this.vtable = this.manager.getVtable(vtableKey);
		}
		else {
			this.vtable = null;
		}
		this.baseKeys = DataBaseUtils.getLongArray(record, SchemaOrdinals.BASE_KEYS.ordinal());
		this.baseOffsets = DataBaseUtils.getIntArray(
			record, SchemaOrdinals.BASE_OFFSETS.ordinal());
		this.virtualKeys = DataBaseUtils.getLongArray(
			record, SchemaOrdinals.VIRTUAL_BASE_KEYS.ordinal());
		this.demangled = doDemangle(symbolName);
	}

	public String getProgramName() {
		return programName;
	}

	private static Demangled doDemangle(String symbolName) {
		Demangled demangled = DemanglerUtil.demangle(symbolName);
		if (demangled == null) {
			throw new AssertException("ArchivedClassTypeInfo symbol "
				+ symbolName + " failed to demangle");
		}
		return demangled.getNamespace();
	}

	public static db.Record createRecord(long key) {
		return SCHEMA.createRecord(key);
	}

	public Address getAddress(Program program) {
		return program.getAddressMap().decodeAddress(address);
	}

	@Override
	protected boolean refresh() {
		return false;
	}

	@Override
	public ArchiveClassTypeInfoManager getManager() {
		return (ArchiveClassTypeInfoManager) manager.getManager();
	}

	public byte getClassId() {
		return classId;
	}

	public String getTypeName() {
		return typeName;
	}

	public String getSymbolName() {
		return symbolName;
	}

	/**
	 * @return the datatype
	 */
	public Structure getDataType() {
		return struct;
	}

	public Structure getSuperDataType() {
		return superStruct;
	}

	public CategoryPath getCategoryPath() {
		return struct.getCategoryPath();
	}

	public ArchivedGnuVtable getArchivedVtable() {
		return vtable;
	}

	public ArchivedClassTypeInfo[] getParentModels() {
		ArchiveClassTypeInfoManager classManager = getManager();
		return Arrays.stream(baseKeys)
				.mapToObj(classManager::getClass)
				.toArray(ArchivedClassTypeInfo[]::new);
	}

	public ArchivedClassTypeInfo[] getArchivedVirtualParents() {
		ArchiveClassTypeInfoManager classManager = getManager();
		return Arrays.stream(virtualKeys)
				.mapToObj(classManager::getClass)
				.toArray(ArchivedClassTypeInfo[]::new);
	}

	/**
	 * @return the baseKeys
	 */
	protected long[] getBaseKeys() {
		return baseKeys;
	}

	protected long[] getVirtualKeys() {
		return virtualKeys;
	}

	/**
	 * @return the baseOffsets
	 */
	public int[] getBaseOffsets() {
		return baseOffsets;
	}

	@Override
	public String getName() {
		return demangled.getDemangledName();
	}

	private static UnsupportedOperationException getUnsupportedMsg(Method method) {
		return new UnsupportedOperationException(
			"Method "+method.getName()+" is not supported for an ArchivedClassTypeInfo");
	}

	@Override
	public Namespace getNamespace() {
		throw getUnsupportedMsg(new Object(){}.getClass().getEnclosingMethod());
	}

	@Override
	public String getIdentifier() {
		return AbstractClassTypeInfoDB.getIdentifier(classId);
	}

	@Override
	public Address getAddress() {
		throw getUnsupportedMsg(new Object(){}.getClass().getEnclosingMethod());
	}

	@Override
	public GhidraClass getGhidraClass() {
		throw getUnsupportedMsg(new Object(){}.getClass().getEnclosingMethod());
	}

	@Override
	public boolean hasParent() {
		return baseKeys.length > 0;
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		return Set.of(getArchivedVirtualParents());
	}

	@Override
	public boolean isAbstract() {
		if (vtable != null) {
			return Arrays.stream(vtable.getFunctionDefinitions())
				.flatMap(Arrays::stream)
				.map(FunctionDefinition::getName)
				.filter(PURE_VIRTUAL_FUNCTION_NAMES::contains)
				.findFirst()
				.isPresent();
		}
		return false;
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		throw getUnsupportedMsg(new Object(){}.getClass().getEnclosingMethod());
	}

	@Override
	public Vtable getVtable() {
		throw getUnsupportedMsg(new Object(){}.getClass().getEnclosingMethod());
	}

	@Override
	public Structure getClassDataType() {
		long id = manager.getTypeRecord(key).getLongValue(SchemaOrdinals.DATATYPE_ID.ordinal());
		return (Structure) getManager().findDataTypeForID(new UniversalID(id));
	}

	@Override
	public SymbolPath getSymbolPath() {
		return new SymbolPath(SymbolPathParser.parse(demangled.getNamespaceString()));
	}

}