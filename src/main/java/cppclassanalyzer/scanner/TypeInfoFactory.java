package cppclassanalyzer.scanner;

import java.util.Map;
import java.util.function.Function;

import ghidra.util.exception.AssertException;

import db.NoTransactionException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;

class TypeInfoFactory {

	private TypeInfoFactory() {}

	private static final Map<String, MethodPair> COPY_MAP =
		Map.ofEntries(
			Map.entry(
				ArrayTypeInfoModel.ID_STRING,
				new MethodPair(
					ArrayTypeInfoModel::getModel,
					ArrayTypeInfoModel::getDataType)),
			Map.entry(
				ClassTypeInfoModel.ID_STRING,
				new MethodPair(
					ClassTypeInfoModel::getModel,
					ClassTypeInfoModel::getDataType)),
			Map.entry(
				EnumTypeInfoModel.ID_STRING,
				new MethodPair(
					EnumTypeInfoModel::getModel,
					EnumTypeInfoModel::getDataType)),
			Map.entry(
				FunctionTypeInfoModel.ID_STRING,
				new MethodPair(
					FunctionTypeInfoModel::getModel,
					FunctionTypeInfoModel::getDataType)),
			Map.entry(
				FundamentalTypeInfoModel.ID_STRING,
				new MethodPair(
					FundamentalTypeInfoModel::getModel,
					FundamentalTypeInfoModel::getDataType)),
			Map.entry(
				PBaseTypeInfoModel.ID_STRING,
				new MethodPair(
					PBaseTypeInfoModel::getModel,
					PBaseTypeInfoModel::getDataType)),
			Map.entry(
				PointerToMemberTypeInfoModel.ID_STRING,
				new MethodPair(
					PointerToMemberTypeInfoModel::getModel,
					PointerToMemberTypeInfoModel::getDataType)),
			Map.entry(
				PointerTypeInfoModel.ID_STRING,
				new MethodPair(
					PointerTypeInfoModel::getModel,
					PointerTypeInfoModel::getDataType)),
			Map.entry(
				SiClassTypeInfoModel.ID_STRING,
				new MethodPair(
					SiClassTypeInfoModel::getModel,
					SiClassTypeInfoModel::getDataType)),
			Map.entry(
				VmiClassTypeInfoModel.ID_STRING,
				new MethodPair(
					VmiClassTypeInfoModel::getModel,
					VmiClassTypeInfoModel::getDataType)),
			Map.entry(
				TypeInfoModel.ID_STRING,
				new MethodPair(
					TypeInfoModel::getModel,
					TypeInfoModel::getDataType)),
			Map.entry(
				IosFailTypeInfoModel.ID_STRING,
				new MethodPair(
					IosFailTypeInfoModel::getModel,
					IosFailTypeInfoModel::getDataType)));

	/**
	 * Get the TypeInfo in the buffer
	 * @param buf the memory buffer containing the TypeInfo data
	 * @return the TypeInfo at the buffers address
	 */
	static TypeInfo getTypeInfo(MemBuffer buf) {
		return getTypeInfo(buf.getMemory().getProgram(), buf.getAddress());
	}

	private static TypeInfo doGetTypeInfo(ModelGetter getter, Program program, Address address)
			throws InvalidDataTypeException {
		try {
			return getter.getModel(program, address);
		} catch (NoTransactionException e) {
			// this is rare occurance where it is better to catch this
			// it is preferred to only create a transaction when necessary
			addTypeInfoTypes(program);
			return getter.getModel(program, address);
		}
	}

	private static void addTypeInfoTypes(Program program) {
		int id = program.startTransaction("Creating typeinfo structures");
		DataTypeManager dtm = program.getDataTypeManager();
		for (MethodPair pair : COPY_MAP.values()) {
			pair.dataTypeGetter.apply(dtm);
		}
		program.endTransaction(id, true);
	}

	/**
	 * Get the TypeInfo at the address
	 * @param program the program containing the TypeInfo
	 * @param address the address of the TypeInfo
	 * @return the TypeInfo at the specified address in the specified program
	 * or null if none exists.
	 */
	static TypeInfo getTypeInfo(Program program, Address address) {
			String baseTypeName = TypeInfoUtils.getIDString(program, address);
			if (!COPY_MAP.containsKey(baseTypeName)) {
				// invalid typeinfo
				return null;
			} try {
				ModelGetter getter = COPY_MAP.get(baseTypeName).modelGetter;
				return doGetTypeInfo(getter, program, address);
			} catch (InvalidDataTypeException e) {
				throw new AssertException(
					TypeInfoUtils.getErrorMessage(program, address, baseTypeName));
			}
	}

	/**
	 * Checks if a valid TypeInfo is located at the start of the buffer
	 * @param buf the memory buffer containing the TypeInfo data
	 * @return true if the buffer contains a valid TypeInfo
	 */
	static boolean isTypeInfo(MemBuffer buf) {
		return buf != null ? isTypeInfo(buf.getMemory().getProgram(), buf.getAddress()) : false;
	}

	/**
	 * Checks if a valid TypeInfo is located at the address in the program.
	 * @param program the program containing the TypeInfo
	 * @param address the address of the TypeInfo
	 * @return true if the data is a valid TypeInfo
	 */
	static boolean isTypeInfo(Program program, Address address) {
		try {
			if (COPY_MAP.containsKey(TypeInfoUtils.getIDString(program, address))) {
				return !TypeInfoUtils.getTypeName(program, address).isBlank();
			}
		} catch (AddressOutOfBoundsException e) {
			return false;
		}
		return false;
	}

	/**
	 * Invokes getDataType on the TypeInfo containing the specified typename
	 * @param program the program containing the TypeInfo
	 * @param typename the type_info class's typename
	 * @return the TypeInfo structure for the typename
	 * @see TypeInfoModel#getDataType()
	 */
	static Structure getDataType(Program program, String typename) {
		if (COPY_MAP.containsKey(typename)) {
			final Function<DataTypeManager, DataType> getter =
				COPY_MAP.get(typename).dataTypeGetter;
			return (Structure) getter.apply(program.getDataTypeManager());
		}
		return null;
	}

	private interface ModelGetter {
		TypeInfo getModel(Program program, Address address) throws InvalidDataTypeException;
	}

	private static final class MethodPair {

		final ModelGetter modelGetter;
		final Function<DataTypeManager, DataType> dataTypeGetter;

		MethodPair(ModelGetter modelGetter,
			Function<DataTypeManager, DataType> dataTypeGetter) {
				this.modelGetter = modelGetter;
				this.dataTypeGetter = dataTypeGetter;
		}
	}

}
