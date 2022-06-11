package cppclassanalyzer.data.typeinfo;

import static cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.LongStream;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.util.NamespaceUtils;

import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.vs.*;

public class VsClassTypeInfoDB extends AbstractClassTypeInfoDB implements VsClassTypeInfo {

	private long[] baseKeys;
	private int[] baseOffsets;
	private long baseModelAddress;
	private long hierarchyDescriptorAddress;
	private final GhidraClass gc;

	public VsClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfoRecord record) {
		super(worker, record);
		this.gc = doGetGhidraClass();
	}

	public VsClassTypeInfoDB(ProgramRttiRecordManager worker, VsClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(worker, type, record);
		this.gc = type.getGhidraClass();
	}

	private GhidraClass doGetGhidraClass() {
		int id = getProgram().startTransaction(getClass().getSimpleName()+": Getting GhidraClass");
		boolean success = false;
		try {
			Namespace ns = getTypeDescriptor().getDescriptorAsNamespace();
			if (!(ns instanceof GhidraClass)) {
				ns = NamespaceUtils.convertNamespaceToClass(ns);
			}
			success = true;
			return (GhidraClass) ns;
		} catch (InvalidInputException e) {
			throw new AssertException(e);
		} finally {
			getProgram().endTransaction(id, success);
		}
	}

	private void fillRecord(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.allocate(getSize());
		ClassTypeInfoRecord.setLongArray(buf, baseKeys);
		ClassTypeInfoRecord.setIntArray(buf, baseOffsets);
		buf.putLong(baseModelAddress);
		buf.putLong(hierarchyDescriptorAddress);
		record.setBinaryData(MODEL_DATA, buf.array());
		manager.updateRecord(record);
	}

	private int getSize() {
		return ClassTypeInfoRecord.getArraySize(baseKeys) +
			ClassTypeInfoRecord.getArraySize(baseOffsets) + Long.BYTES * 3;
	}

	@Override
	public boolean hasParent() {
		return baseKeys.length > 0;
	}

	@Override
	public ClassTypeInfoDB[] getParentModels() {
		return LongStream.of(baseKeys)
			.mapToObj(manager::getType)
			.toArray(ClassTypeInfoDB[]::new);
	}

	static boolean isVirtual(Rtti1Model model) throws InvalidDataTypeException {
		return (model.getAttributes() >> 4 & 1) == 1;
	}

	private ClassTypeInfo getParent(Rtti1Model model) {
		try {
			return manager.getManager().getType(model.getRtti0Address());
		} catch (InvalidDataTypeException e) {
			invalidError(e);
		}
		return null;
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		try {
			Set<ClassTypeInfo> result = new LinkedHashSet<>();
			Rtti3Model rtti3 = getHierarchyDescriptor();
			if (rtti3 == null) {
				return Collections.emptySet();
			}
			Rtti2Model baseArray = rtti3.getRtti2Model();
			for (int i = 1; i < rtti3.getRtti1Count(); i++) {
				Rtti1Model model = baseArray.getRtti1Model(i);
				ClassTypeInfo parent = getParent(model);
				result.addAll(parent.getVirtualParents());
				if (isVirtual(model)) {
					result.add(getManager().getType(model.getRtti0Address()));
				}
			}
			return result;
		} catch (InvalidDataTypeException e) {
			invalidError(e);
		}
		return null;
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		if (isVtableSearched()) {
			return getVtable();
		}
		RttiModelWrapper wrapper = RttiModelWrapper.getWrapper(getTypeDescriptorModel(), monitor);
		Vtable vtable = wrapper.findVtable(monitor);
		setVtableSearched();
		if (Vtable.isValid(vtable)) {
			vtable = manager.resolve(vtable);
			setVtable(vtable);
		}
		return vtable;
	}

	public static long[] getBaseKeys(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		return ClassTypeInfoRecord.getLongArray(buf);
	}

	@Override
	public Rtti1Model getBaseModel() {
		if (baseModelAddress != INVALID_KEY) {
			return new Rtti1Model(getProgram(), decodeAddress(baseModelAddress), DEFAULT_OPTIONS);
		}
		return null;
	}

	@Override
	public Rtti2Model getBaseClassArray() {
		Rtti3Model model = getHierarchyDescriptor();
		if (model != null) {
			try {
				return model.getRtti2Model();
			} catch (InvalidDataTypeException e) {
				throw new AssertException(e);
			}
		}
		return null;
	}

	@Override
	public Rtti3Model getHierarchyDescriptor() {
		if (hierarchyDescriptorAddress != INVALID_KEY) {
			Address rtti3Address = decodeAddress(hierarchyDescriptorAddress);
			return new Rtti3Model(getProgram(), rtti3Address, DEFAULT_OPTIONS);
		}
		return null;
	}

	public static int getBaseCount(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		return ClassTypeInfoRecord.getLongArray(buf).length;
	}

	public static void updateRecord(ClassTypeInfoRecord record, LongIntHashtable keyMap) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] baseKeys = ClassTypeInfoRecord.getLongArray(buf);
		int[] baseOffsets = ClassTypeInfoRecord.getIntArray(buf);
		long baseModelAddress = buf.getLong();
		long hierarchyDescriptorAddress = buf.getLong();
		updateKeys(baseKeys, keyMap);
		buf = ByteBuffer.allocate(buf.array().length);
		ClassTypeInfoRecord.setLongArray(buf, baseKeys);
		ClassTypeInfoRecord.setIntArray(buf, baseOffsets);
		buf.putLong(baseModelAddress);
		buf.putLong(hierarchyDescriptorAddress);
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

	private void invalidError(InvalidDataTypeException e) {
		throw new AssertException(
			"Ghidra-Cpp-Class-Analyzer: previously validated data is no longer valid?", e);
	}

	@Override
	protected String getPureVirtualFunctionName() {
		return VsVtableModel.PURE_VIRTUAL_FUNCTION_NAME;
	}

	private TypeDescriptorModel getTypeDescriptorModel() {
		return new TypeDescriptorModel(getProgram(), getAddress(), DEFAULT_OPTIONS);
	}

	@Override
	protected VsCppClassBuilder getClassBuilder() {
		return new VsCppClassBuilder(this);
	}

	@Override
	protected void fillModelData(ClassTypeInfoRecord record) {
		byte[] data = getClassData(record);
		if (data != null) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			this.baseKeys = ClassTypeInfoRecord.getLongArray(buf);
			this.baseOffsets = ClassTypeInfoRecord.getIntArray(buf);
			this.baseModelAddress = buf.getLong();
			this.hierarchyDescriptorAddress = buf.getLong();
		} else {
			fillModelData(getRawType(), record);
		}
	}

	@Override
	public TypeDescriptorModel getTypeDescriptor() {
		return new TypeDescriptorModel(getProgram(), getAddress(), DEFAULT_OPTIONS);
	}

	@Override
	protected void fillModelData(ClassTypeInfo type, ClassTypeInfoRecord record) {
		VsClassTypeInfo vsType = (VsClassTypeInfo) type;
		List<Map.Entry<ClassTypeInfo, Integer>> baseEntries =
			new ArrayList<>(
				vsType.getBaseOffsets()
				.entrySet()
			);
		baseKeys = new long[baseEntries.size()];
		baseOffsets = new int[baseEntries.size()];
		for (int i = 0; i < baseKeys.length; i++) {
			Map.Entry<ClassTypeInfo, Integer> entry = baseEntries.get(i);
			baseKeys[i] = manager.resolve(entry.getKey()).getKey();
			baseOffsets[i] = entry.getValue();
		}
		Rtti1Model base = vsType.getBaseModel();
		baseModelAddress = base != null ? encodeAddress(base.getAddress()) : INVALID_KEY;
		Rtti3Model model = vsType.getHierarchyDescriptor();
		hierarchyDescriptorAddress = model != null
			? encodeAddress(model.getAddress()) : INVALID_KEY;
		fillRecord(record);
	}
}
