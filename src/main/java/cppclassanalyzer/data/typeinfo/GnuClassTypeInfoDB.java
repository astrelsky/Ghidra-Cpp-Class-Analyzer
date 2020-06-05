package cppclassanalyzer.data.typeinfo;

import static cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields.*;

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
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.BaseClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.util.datastruct.IntArrayList;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.datastruct.LongIntHashtable;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;

public class GnuClassTypeInfoDB extends AbstractClassTypeInfoDB {

	private final GhidraClass gc;
	private long[] nonVirtualBaseKeys;
	private long[] virtualBaseKeys;
	private long[] baseKeys;
	private int[] baseOffsets;

	public GnuClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfoRecord record) {
		super(worker, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName());
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		this.nonVirtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		this.virtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		this.baseKeys = ClassTypeInfoRecord.getLongArray(buf);
		this.baseOffsets = ClassTypeInfoRecord.getIntArray(buf);
	}

	public GnuClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(worker, type, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName());
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

	public GnuClassTypeInfoDB(ProgramRttiRecordManager worker, ArchivedClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(worker, type, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName());
		ClassTypeInfoManager aMan = type.getManager();
		this.nonVirtualBaseKeys = extractKeys(aMan, type.getNonVirtualBaseKeys());
		this.virtualBaseKeys = extractKeys(aMan, type.getVirtualKeys());
		this.baseKeys = extractKeys(aMan, type.getBaseKeys());
		this.baseOffsets = type.getBaseOffsets();
		fillRecord(record);
	}

	private long[] extractKeys(ClassTypeInfoManager aMan, long[] keys) {
		return Arrays.stream(keys)
				.mapToObj(aMan::getType)
				.map(ArchivedClassTypeInfo.class::cast)
				.map(manager::resolve)
				.mapToLong(DatabaseObject::getKey)
				.toArray();
	}

	private void fillRecord(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.allocate(getSize());
		ClassTypeInfoRecord.setLongArray(buf, nonVirtualBaseKeys);
		ClassTypeInfoRecord.setLongArray(buf, virtualBaseKeys);
		ClassTypeInfoRecord.setLongArray(buf, baseKeys);
		ClassTypeInfoRecord.setIntArray(buf, baseOffsets);
		record.setBinaryData(MODEL_DATA, buf.array());
		manager.updateRecord(record);
	}

	private void fillBaseOffsets(LongArrayList keys, IntArrayList offsets) {
		// Primitive TypeInfos are not database objects.
		// Calling getTypeInfo results in a non-database object ClassTypeInfo
		ClassTypeInfo type = (ClassTypeInfo) getManager().getTypeInfo(getAddress(), false);
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
		return Integer.BYTES + Long.BYTES * nonVirtualBaseKeys.length + Integer.BYTES +
			Long.BYTES * virtualBaseKeys.length + Integer.BYTES + Long.BYTES * baseKeys.length +
			Integer.BYTES + Integer.BYTES * baseOffsets.length;
	}

	@Override
	public boolean hasParent() {
		return nonVirtualBaseKeys.length > 0 || virtualBaseKeys.length > 0;
	}

	@Override
	public ClassTypeInfoDB[] getParentModels() {
		return LongStream.concat(
			LongStream.of(nonVirtualBaseKeys),
			LongStream.of(virtualBaseKeys))
				.mapToObj(manager::getType)
				.toArray(ClassTypeInfoDB[]::new);

	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		return LongStream.of(virtualBaseKeys)
				.mapToObj(manager::getType)
				.collect(Collectors.toSet());
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		if (isVtableSearched()) {
			return getVtable();
		}
		setVtableSearched();
		Vtable vtable = ClassTypeInfoUtils.findVtable(getProgram(), this, monitor);
		if (Vtable.isValid(vtable)) {
			setVtable(vtable);
			return getVtable();
		}
		return vtable;
	}

	public static long[] getBaseKeys(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] nonVirtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		long[] virtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		return LongStream.concat(
			LongStream.of(nonVirtualBaseKeys),
			LongStream.of(virtualBaseKeys)).toArray();
	}

	public static int getBaseCount(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] nonVirtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		long[] virtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		return nonVirtualBaseKeys.length + virtualBaseKeys.length;
	}

	public static void updateRecord(ClassTypeInfoRecord record, LongIntHashtable keyMap) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] nonVirtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		long[] virtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
		updateKeys(nonVirtualBaseKeys, keyMap);
		updateKeys(virtualBaseKeys, keyMap);
		buf = ByteBuffer.allocate(buf.array().length);
		ClassTypeInfoRecord.setLongArray(buf, nonVirtualBaseKeys);
		ClassTypeInfoRecord.setLongArray(buf, virtualBaseKeys);
		record.setBinaryData(MODEL_DATA, buf.array());
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
	protected boolean refresh(ClassTypeInfoRecord record) {
		if (super.refresh(record)) {
			ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
			nonVirtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
			virtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
			long[] tmpBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
			int[] tmpBaseOffsets = ClassTypeInfoRecord.getIntArray(buf);
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

	@Override
	public Namespace getNamespace() {
		return gc;
	}

	@Override
	protected String getPureVirtualFunctionName() {
		return GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;
	}

	@Override
	protected GccCppClassBuilder getClassBuilder() {
		return new GccCppClassBuilder(this);
	}
}