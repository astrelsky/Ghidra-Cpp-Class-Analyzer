package ghidra.program.database.data.rtti.typeinfo;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.WindowsClassTypeInfo;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.database.data.rtti.DataBaseUtils;
import ghidra.program.database.data.rtti.manager.recordmanagers.ProgramRttiRecordManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WindowsClassTypeInfoDB extends AbstractClassTypeInfoDB implements WindowsClassTypeInfo {

	private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

	private final long[] baseKeys;
	private final int[] baseOffsets;
	private final long baseModelAddress;
	private final long hierarchyDescriptorAddress;

	public WindowsClassTypeInfoDB(ProgramRttiRecordManager worker, db.Record record) {
		super(worker, record);
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		baseKeys = DataBaseUtils.getLongArray(buf);
		baseOffsets = DataBaseUtils.getIntArray(buf);
		baseModelAddress = buf.getLong();
		hierarchyDescriptorAddress = buf.getLong();
	}

	public WindowsClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfo type, db.Record record) {
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
		DataBaseUtils.putLongArray(buf, baseKeys);
		DataBaseUtils.putIntArray(buf, baseOffsets);
		buf.putLong(baseModelAddress);
		buf.putLong(hierarchyDescriptorAddress);
		record.setBinaryData(SchemaOrdinals.MODEL_DATA.ordinal(), buf.array());
	}

	private int getSize() {
		return
			baseKeys.length * Long.BYTES
			+ baseOffsets.length * Integer.BYTES
			+ Long.BYTES * 2;
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

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		try {
			Set<ClassTypeInfo> result = new LinkedHashSet<>();
			Rtti3Model rtti3 = getHierarchyDescriptor();
			Rtti2Model baseArray = rtti3.getRtti2Model();
			for (int i = 1; i < rtti3.getRtti1Count(); i++) {
				Rtti1Model model = baseArray.getRtti1Model(i);
				ClassTypeInfo parent = manager.getType(baseKeys[i]);
				result.addAll(parent.getVirtualParents());
				if (isVirtual(model)) {
					result.add(getManager().getType(model.getRtti0Address()));
				}
			}
			return result;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(
				"Ghidra-Cpp-Class-Analyzer: previously validated data is no longer valid?", e);
		}
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		return getVtable();
	}

	@Override
	protected Namespace buildNamespace() {
		TypeDescriptorModel type = new TypeDescriptorModel(
			getProgram(), address, DEFAULT_OPTIONS);
		return type.getDescriptorAsNamespace();
	}

	public static long[] getBaseKeys(db.Record record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		return DataBaseUtils.getLongArray(buf);
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

	public static int getBaseCount(db.Record record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		return DataBaseUtils.getLongArray(buf).length;
	}

	public static void updateRecord(db.Record record, LongIntHashtable keyMap) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		long[] baseKeys = DataBaseUtils.getLongArray(buf);
		int[] baseOffsets = DataBaseUtils.getIntArray(buf);
		long baseModelAddress = buf.getLong();
		long hierarchyDescriptorAddress = buf.getLong();
		updateKeys(baseKeys, keyMap);
		buf = ByteBuffer.allocate(buf.array().length);
		DataBaseUtils.putLongArray(buf, baseKeys);
		DataBaseUtils.putIntArray(buf, baseOffsets);
		buf.putLong(baseModelAddress);
		buf.putLong(hierarchyDescriptorAddress);
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

	@Override
	protected boolean refresh() {
		// no refresh required
		return true;
	}
}