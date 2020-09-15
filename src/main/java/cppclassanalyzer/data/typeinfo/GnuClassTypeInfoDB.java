package cppclassanalyzer.data.typeinfo;

import static cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.GccCppClassBuilder;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.BaseClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;

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
	}

	public GnuClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(worker, type, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName());
	}

	public GnuClassTypeInfoDB(ProgramRttiRecordManager worker, ArchivedClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(worker, type, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName());
		ClassTypeInfoManager aMan = type.getManager();
		this.nonVirtualBaseKeys = extractKeys(aMan, type.getNonVirtualBaseKeys());
		this.virtualBaseKeys = extractKeys(aMan, type.getVirtualKeys());
		this.baseKeys = extractKeys(aMan, type.getBaseKeys());
		this.baseOffsets = type.getBaseOffsetValues();
		fillRecord(record);
		setVtableSearched();
		Vtable vtable = type.getVtable();
		if (Vtable.isValid(vtable)) {
			vtable = worker.resolve(vtable);
			setVtable(vtable);
		}
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

	private int getSize() {
		return ClassTypeInfoRecord.getArraySize(nonVirtualBaseKeys)
			+ ClassTypeInfoRecord.getArraySize(virtualBaseKeys)
			+ ClassTypeInfoRecord.getArraySize(baseKeys)
			+ ClassTypeInfoRecord.getArraySize(baseOffsets);
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
	protected void fillModelData(ClassTypeInfoRecord record) {
		byte[] data = getClassData(record);
		if (data != null) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			nonVirtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
			virtualBaseKeys = ClassTypeInfoRecord.getLongArray(buf);
			baseKeys = ClassTypeInfoRecord.getLongArray(buf);
			baseOffsets = ClassTypeInfoRecord.getIntArray(buf);
			if (nonVirtualBaseKeys.length == 0 && virtualBaseKeys.length == 0) {
				return;
			}
			if (baseKeys.length == 0 && baseOffsets.length == 0 && isVtableSearched()) {
				baseKeys = getBaseKeys(record);
				baseOffsets = doGetBaseOffsets();
				fillRecord(record);
			}
		} else {
			fillModelData(getRawType(), record);
		}
	}

	private int[] doGetBaseOffsets() {
		return Stream.concat(doGetOffsets().stream(), getSortedOffsets().stream())
			.mapToInt(Long::intValue)
			.toArray();
	}

	List<Long> doGetOffsets() {
		if (getTypeId() == TypeId.VMI_CLASS) {
			BaseClassTypeInfoModel[] bases = getBases();
			LongArrayList result = new LongArrayList();
			for (BaseClassTypeInfoModel base : bases) {
				if(!base.isVirtual()) {
					result.add((long) base.getOffset());
				}
			}
			return result;
		}
		if (nonVirtualBaseKeys.length == 1) {
			return List.of(0L);
		}
		return Collections.emptyList();
	}

	List<Long> getSortedOffsets() {
		GnuVtable vtable = (GnuVtable) getVtable();
		if (Vtable.isValid(vtable)) {
			List<Long> offsets = new ArrayList<>(vtable.getPrefixes().get(0).getOffsets());
			if (offsets.size() > 0) {
				offsets.sort(null);
				offsets.remove(0);
			}
			return offsets;
		}
		return Collections.emptyList();
	}

	private BaseClassTypeInfoModel[] getBases() {
		return VmiClassTypeInfoModel.getBases(getProgram(), getAddress());
	}

	@Override
	protected boolean refresh(ClassTypeInfoRecord record) {
		if (super.refresh(record)) {
			fillModelData(record);
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
		return GnuVtable.PURE_VIRTUAL_FUNCTION_NAME;
	}

	@Override
	protected GccCppClassBuilder getClassBuilder() {
		return new GccCppClassBuilder(this);
	}

	@Override
	protected void fillModelData(ClassTypeInfo type, ClassTypeInfoRecord record) {
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
		baseKeys = new long[0];
		baseOffsets = new int[0];
		fillRecord(record);
	}
}
