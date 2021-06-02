package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import cppclassanalyzer.data.manager.ItaniumAbiClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;

/**
 * Model for the {@value #STRUCTURE_NAME} helper class.
 */
public final class BaseClassTypeInfoModel {

	private static final String DESCRIPTION =
		"Helper data type for the __base_class_type_info array";
	static final String STRUCTURE_NAME = "__base_class_type_info";
	static final int FLAGS_ORDINAL = 1;

	private final ItaniumAbiClassTypeInfoManager manager;
	private MemoryBufferImpl buf;
	private DataTypeManager dtm;

	BaseClassTypeInfoModel(Program program, Address address) {
		this.manager = (ItaniumAbiClassTypeInfoManager) CppClassAnalyzerUtils.getManager(program);
		this.buf = new MemoryBufferImpl(program.getMemory(), address);
		this.dtm = program.getDataTypeManager();
	}

	/**
	 * Checks if this base class is inherited virtually
	 * @return true if this base class is inherited virtually
	 */
	public boolean isVirtual() {
		Structure struct = (Structure) getDataType();
		int offset = struct.getComponent(1).getOffset();
		MemBuffer tmpBuf = new DumbMemBufferImpl(buf.getMemory(), buf.getAddress().add(offset));
		return VmiOffsetFlagsModel.isVirtual(tmpBuf, dtm);
	}

	/**
	 * Checks if this base class is inherited publically
	 * @return true if this base class is inherited publically
	 */
	public boolean isPublic() {
		Structure struct = (Structure) getDataType();
		int offset = struct.getComponent(1).getOffset();
		MemBuffer tmpBuf = new DumbMemBufferImpl(buf.getMemory(), buf.getAddress().add(offset));
		return VmiOffsetFlagsModel.isPublic(tmpBuf, dtm);
	}

	/**
	 * Gets the value of this base class's offset
	 * @return the value of this base class's offset
	 */
	public int getOffset() {
		return (int) getFlags().getOffset();
	}

	/**
	 * Gets the {@value #STRUCTURE_NAME} datatype
	 * @return the {@value #STRUCTURE_NAME} datatype
	 */
	public DataType getDataType() {
		return getDataType(dtm);
	}

	/**
	 * Gets the address of this {@value #STRUCTURE_NAME}
	 * @return the address of this {@value #STRUCTURE_NAME}
	 */
	public Address getAddress() {
		return buf.getAddress();
	}

	VmiOffsetFlagsModel getFlags() {
		Structure struct = (Structure) getDataType();
		int offset = struct.getComponent(1).getOffset();
		return new VmiOffsetFlagsModel(manager.getProgram(), buf.getAddress().add(offset));
	}

	/**
	 * Gets the {@value #STRUCTURE_NAME} datatype
	 * @param dtm the DataTypeManager
	 * @return the {@value #STRUCTURE_NAME} datatype
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		DataType superDt = ClassTypeInfoModel.getPointer(dtm);
		DataType existingDt = dtm.getDataType(superDt.getCategoryPath(), STRUCTURE_NAME);
		if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
			return existingDt;
		}
		DataType flags = VmiOffsetFlagsModel.getDataType(dtm);
		StructureDataType struct = new StructureDataType(superDt.getCategoryPath(), STRUCTURE_NAME, 0, dtm);
		struct.add(superDt, superDt.getLength(), "super___class_type_info", null);
		struct.add(flags, flags.getLength(), "__offset_flags", null);
		struct.setPackingEnabled(true);
		struct.setDescription(DESCRIPTION);
		DataType result = dtm.resolve(struct, KEEP_HANDLER);
		return result.getLength() <= 1 ? dtm.resolve(struct, REPLACE_HANDLER) : result;
	}

	/**
	 * Gets the ClassTypeInfo model for this base class
	 * @return the ClassTypeInfo
	 */
	public ClassTypeInfo getClassModel() {
		Program program = manager.getProgram();
		Address classAddress = getClassAddress();
		if (!GnuUtils.isExternal(program, classAddress)) {
			return manager.getType(classAddress);
		}
		return manager.getExternalClassTypeInfo(classAddress);
	}

	/**
	 * Gets the base ClassTypeInfo's name
	 * @return the base ClassTypeInfo's name
	 * @see ClassTypeInfo#getName()
	 */
	public String getName() {
		return getClassModel().getName();
	}

	/**
	 * Gets the base ClassTypeInfo's address
	 * @return the base ClassTypeInfo's address
	 * @see ClassTypeInfo#getAddress()
	 */
	public Address getClassAddress() {
		Pointer pointer = ClassTypeInfoModel.getPointer(dtm);
		return (Address) pointer.getValue(buf, pointer.getDefaultSettings(), -1);
	}

	void advance() {
		try {
			this.buf.advance(getDataType().getLength());
		} catch (AddressOverflowException e) {
			Msg.error(this, e);
		}
	}

	public Set<BaseClassTypeInfoModel> getVirtualBases() {
		TypeInfo type = manager.getTypeInfo(getClassAddress(), false);
		if (!(type instanceof VmiClassTypeInfoModel)) {
			if (isVirtual()) {
				return Set.of(this);
			}
			return Collections.emptySet();
		}
		VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) type;
		Set<BaseClassTypeInfoModel> result = Arrays.stream(vmi.getBases())
			.map(BaseClassTypeInfoModel::getVirtualBases)
			.flatMap(Set::stream)
			.filter(BaseClassTypeInfoModel::isVirtual)
			.collect(Collectors.toSet());
		if (isVirtual()) {
			result.add(this);
		}
		return result;
	}
}
