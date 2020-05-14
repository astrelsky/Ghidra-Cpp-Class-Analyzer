package ghidra.program.database.data.rtti.typeinfo;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.BaseClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.rtti.ArchiveClassTypeInfoManager;
import ghidra.program.database.data.rtti.ClassTypeInfoManagerDB;
import ghidra.program.database.data.rtti.DataBaseUtils;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.IntArrayList;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.datastruct.LongIntHashtable;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import db.Record;

public class GnuClassTypeInfoDB extends AbstractClassTypeInfoDB {

	private long[] nonVirtualBaseKeys;
	private long[] virtualBaseKeys;
	private long[] baseKeys;
	private int[] baseOffsets;

	public GnuClassTypeInfoDB(ClassTypeInfoManagerDB manager,
		DBObjectCache<AbstractClassTypeInfoDB> cache, db.Record record) {
		super(manager, cache, record);
		refresh(record);
	}

	public GnuClassTypeInfoDB(ClassTypeInfoManagerDB manager, DBObjectCache<AbstractClassTypeInfoDB> cache,
			ClassTypeInfo type, db.Record record) {
		super(manager, cache, type, record);
		if (type.hasParent()) {
			virtualBaseKeys = type.getVirtualParents()
				.stream()
				.map(manager::resolve)
				.mapToLong(DatabaseObject::getKey)
				.toArray();
		} else {
			virtualBaseKeys = new long[0];
		}
		if (type instanceof VmiClassTypeInfoModel) {
			VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) type;
			nonVirtualBaseKeys =
				Arrays.stream(vmi.getBases())
					.filter(Predicate.not(BaseClassTypeInfoModel::isVirtual))
					.map(BaseClassTypeInfoModel::getClassModel)
					.map(manager::resolve)
					.mapToLong(DatabaseObject::getKey)
					.toArray();
		} else if (type.hasParent()) {
			nonVirtualBaseKeys =
				Arrays.stream(type.getParentModels())
					.map(manager::resolve)
					.mapToLong(DatabaseObject::getKey)
					.toArray();
		} else {
			nonVirtualBaseKeys = new long[0];
		}
		if (getVtableSearched()) {
			LongArrayList keys = new LongArrayList();
			IntArrayList offsets = new IntArrayList();
			fillBaseOffsets(keys, offsets);
			baseKeys = keys.toLongArray();
			baseOffsets = offsets.toArray();
		} else {
			baseKeys = new long[0];
			baseOffsets = new int[0];
		}
		fillRecord(record);
	}

	public GnuClassTypeInfoDB(ClassTypeInfoManagerDB manager,
			DBObjectCache<AbstractClassTypeInfoDB> cache, ArchivedClassTypeInfo type,
			Record record) {
		super(manager, cache, type, record);
		this.nonVirtualBaseKeys = type.getBaseKeys();
		this.virtualBaseKeys = type.getVirtualKeys();
		ArchiveClassTypeInfoManager aMan = type.getManager();
		this.baseKeys = Arrays.stream(type.getBaseKeys())
			.mapToObj(aMan::getClass)
			.map(manager::resolve)
			.mapToLong(DatabaseObject::getKey)
			.toArray();
		this.baseOffsets = type.getBaseOffsets();
	}

	private void fillRecord(db.Record record) {
		ByteBuffer buf = ByteBuffer.allocate(getSize());
		DataBaseUtils.putLongArray(buf, nonVirtualBaseKeys);
		DataBaseUtils.putLongArray(buf, virtualBaseKeys);
		DataBaseUtils.putLongArray(buf, baseKeys);
		DataBaseUtils.putIntArray(buf, baseOffsets);
		record.setBinaryData(SchemaOrdinals.MODEL_DATA.ordinal(), buf.array());
		manager.updateRecord(record);
	}

	private void fillBaseOffsets(LongArrayList keys, IntArrayList offsets) {
		ClassTypeInfo type = (ClassTypeInfo) manager.getTypeInfo(address, false);
		List<Map.Entry<ClassTypeInfo, Integer>> baseEntries =
			ClassTypeInfoUtils.getBaseOffsets(type)
			.entrySet()
			.stream()
			.collect(Collectors.toList());
		for (int i = 0; i < baseEntries.size(); i++) {
			Map.Entry<ClassTypeInfo, Integer> entry = baseEntries.get(i);
			keys.add(manager.resolve(entry.getKey()).getKey());
			offsets.add(entry.getValue());
		}
	}

	private int getSize() {
		return Integer.BYTES + Long.BYTES * nonVirtualBaseKeys.length
			+ Integer.BYTES + Long.BYTES * virtualBaseKeys.length
			+ Integer.BYTES + Long.BYTES * baseKeys.length
			+ Integer.BYTES + Integer.BYTES * baseOffsets.length;
	}

	@Override
	protected Namespace buildNamespace() {
		return TypeInfoUtils.getNamespaceFromTypeName(getProgram(), typename);
	}

	@Override
	public boolean hasParent() {
		return nonVirtualBaseKeys.length > 0 || virtualBaseKeys.length > 0;
	}

	@Override
	public ClassTypeInfoDB[] getParentModels() {
		return LongStream.concat(
			LongStream.of(nonVirtualBaseKeys),
			LongStream.of(virtualBaseKeys)).mapToObj(manager::getClass)
				.toArray(ClassTypeInfoDB[]::new);

	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		return LongStream.of(virtualBaseKeys)
			.mapToObj(manager::getClass)
			.collect(Collectors.toSet());
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		if (vtableSearched) {
			return getVtable();
		}
		db.Record record = getRecord();
		vtableSearched = true;
		record.setBooleanValue(SchemaOrdinals.VTABLE_SEARCHED.ordinal(), true);
		manager.updateRecord(record);
		Vtable vtable = ClassTypeInfoUtils.findVtable(getProgram(), this, monitor);
		if (Vtable.isValid(vtable)) {
			setVtable(vtable);
			return getVtable();
		}
		return vtable;
	}

	public static long[] getBaseKeys(db.Record record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] nonVirtualBaseKeys = DataBaseUtils.getLongArray(buf);
		long[] virtualBaseKeys = DataBaseUtils.getLongArray(buf);
		return LongStream.concat(
			LongStream.of(nonVirtualBaseKeys),
			LongStream.of(virtualBaseKeys)).toArray();
	}

	public static int getBaseCount(db.Record record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] nonVirtualBaseKeys = DataBaseUtils.getLongArray(buf);
		long[] virtualBaseKeys = DataBaseUtils.getLongArray(buf);
		return nonVirtualBaseKeys.length + virtualBaseKeys.length;
	}

	public static void updateRecord(db.Record record, LongIntHashtable keyMap) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] nonVirtualBaseKeys = DataBaseUtils.getLongArray(buf);
		long[] virtualBaseKeys = DataBaseUtils.getLongArray(buf);
		updateKeys(nonVirtualBaseKeys, keyMap);
		updateKeys(virtualBaseKeys, keyMap);
		buf = ByteBuffer.allocate(buf.array().length);
		DataBaseUtils.putLongArray(buf, nonVirtualBaseKeys);
		DataBaseUtils.putLongArray(buf, virtualBaseKeys);
		record.setBinaryData(SchemaOrdinals.MODEL_DATA.ordinal(), buf.array());
	}

	@Override
	protected long[] getBaseKeys() {
		return baseKeys;
	}

	@Override
	protected int[] getOffsets() {
		return baseOffsets;
	}

	protected long[] getNonVirtualBaseKeys() {
		return nonVirtualBaseKeys;
	}

	protected long[] getVirtualBaseKeys() {
		return virtualBaseKeys;
	}

	@Override
	public Vtable getVtable() {
		return super.getVtable();
	}

	@Override
	protected boolean refresh(db.Record record) {
		if (super.refresh(record)) {
			ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
			nonVirtualBaseKeys = DataBaseUtils.getLongArray(buf);
			virtualBaseKeys = DataBaseUtils.getLongArray(buf);
			long[] tmpBaseKeys = DataBaseUtils.getLongArray(buf);
			int[] tmpBaseOffsets = DataBaseUtils.getIntArray(buf);
			if (tmpBaseKeys.length == 0 && tmpBaseOffsets.length == 0 && getVtableSearched()) {
				LongArrayList keys = new LongArrayList();
				IntArrayList offsets = new IntArrayList();
				fillBaseOffsets(keys, offsets);
				baseKeys = keys.toLongArray();
				baseOffsets = offsets.toArray();
				fillRecord(record);
			} else {
				baseKeys = tmpBaseKeys;
				baseOffsets = tmpBaseOffsets;
			}
			return true;
		}
		return false;
	}
}