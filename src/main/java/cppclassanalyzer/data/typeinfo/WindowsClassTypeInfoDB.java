package cppclassanalyzer.data.typeinfo;

import static cppclassanalyzer.database.schema.fields.ClassTypeInfoSchemaFields.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.VsCppClassBuilder;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.WindowsClassTypeInfo;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.database.record.ClassTypeInfoRecord;

public class WindowsClassTypeInfoDB extends AbstractClassTypeInfoDB
		implements WindowsClassTypeInfo {

	private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

	private final long[] baseKeys;
	private final int[] baseOffsets;
	private final long baseModelAddress;
	private final long hierarchyDescriptorAddress;

	public WindowsClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfoRecord record) {
		super(worker, record);
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		baseKeys = ClassTypeInfoRecord.getLongArray(buf);
		baseOffsets = ClassTypeInfoRecord.getIntArray(buf);
		baseModelAddress = buf.getLong();
		hierarchyDescriptorAddress = buf.getLong();
	}

	public WindowsClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfo type,
			ClassTypeInfoRecord record) {
		super(worker, type, record);
		WindowsClassTypeInfo model = (WindowsClassTypeInfo) type;
		List<Map.Entry<ClassTypeInfo, Integer>> baseEntries =
			model.getBaseOffsets().entrySet().stream().collect(Collectors.toList());
		baseKeys = new long[baseEntries.size()];
		baseOffsets = new int[baseEntries.size()];
		for (int i = 0; i < baseKeys.length; i++) {
			Map.Entry<ClassTypeInfo, Integer> entry = baseEntries.get(i);
			baseKeys[i] = manager.resolve(entry.getKey()).getKey();
			baseOffsets[i] = entry.getValue();
		}
		baseModelAddress = getManager().encodeAddress(model.getBaseModel().getAddress());
		hierarchyDescriptorAddress = getManager().encodeAddress(
			model.getHierarchyDescriptor().getAddress());
		ByteBuffer buf = ByteBuffer.allocate(getSize());
		ClassTypeInfoRecord.setLongArray(buf, baseKeys);
		ClassTypeInfoRecord.setIntArray(buf, baseOffsets);
		buf.putLong(baseModelAddress);
		buf.putLong(hierarchyDescriptorAddress);
		record.setBinaryData(MODEL_DATA, buf.array());
	}

	private int getSize() {
		return ClassTypeInfoRecord.getArraySize(baseKeys) +
			ClassTypeInfoRecord.getArraySize(baseOffsets) + Long.BYTES * 2;
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
			Supplier<AssertException> e = () -> new AssertException(
				"Parent for " + model.toString() + " not found");
			Address parentAddress = model.getRtti0Address();
			return Arrays.stream(baseKeys)
				.mapToObj(manager::getType)
				.filter(Objects::nonNull)
				.filter(t -> t.getAddress().equals(parentAddress))
				.findFirst()
				.orElseThrow(e);
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
		RttiModelWrapper wrapper = RttiModelWrapper.getWrapper(getTypeDescriptorModel());
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

	public Rtti1Model getBaseModel() {
		return new Rtti1Model(
			getProgram(), getManager().decodeAddress(baseModelAddress), DEFAULT_OPTIONS);
	}

	@Override
	public Rtti3Model getHierarchyDescriptor() {
		Address rtti3Address = getManager().decodeAddress(hierarchyDescriptorAddress);
		return new Rtti3Model(getProgram(), rtti3Address, DEFAULT_OPTIONS);
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
	protected boolean refresh() {
		// no refresh required
		return true;
	}

	@Override
	public Namespace getNamespace() {
		return getBaseModel().getRtti0Model().getDescriptorAsNamespace();
	}

	private void invalidError(InvalidDataTypeException e) {
		throw new AssertException(
			"Ghidra-Cpp-Class-Analyzer: previously validated data is no longer valid?", e);
	}

	@Override
	protected String getPureVirtualFunctionName() {
		return PURE_VIRTUAL_FUNCTION_NAME;
	}

	private TypeDescriptorModel getTypeDescriptorModel() {
		return new TypeDescriptorModel(getProgram(), getAddress(), DEFAULT_OPTIONS);
	}

	@Override
	protected VsCppClassBuilder getClassBuilder() {
		return new VsCppClassBuilder(this);
	}

	@Override
	protected void fillOffsets(ClassTypeInfoRecord record) {
	}
}
