package ghidra.app.cmd.data.rtti.gcc.factory;

import java.util.Map;
import java.util.function.BiFunction;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;

public class TypeInfoFactory {

    private static final String ID_FIELD = "ID_STRING";

    private TypeInfoFactory() {}

	private static final Map<String, BiFunction<Program, Address, TypeInfo>> COPY_MAP =
		Map.ofEntries(
			Map.entry(ArrayTypeInfoModel.ID_STRING, ArrayTypeInfoModel::getModel),
			Map.entry(ClassTypeInfoModel.ID_STRING, ClassTypeInfoModel::getModel),
			Map.entry(EnumTypeInfoModel.ID_STRING, EnumTypeInfoModel::getModel),
			Map.entry(FunctionTypeInfoModel.ID_STRING, FunctionTypeInfoModel::getModel),
			Map.entry(FundamentalTypeInfoModel.ID_STRING, FundamentalTypeInfoModel::getModel),
			Map.entry(PBaseTypeInfoModel.ID_STRING, PBaseTypeInfoModel::getModel),
			Map.entry(PointerToMemberTypeInfoModel.ID_STRING, PointerToMemberTypeInfoModel::getModel),
			Map.entry(PointerTypeInfoModel.ID_STRING, PointerTypeInfoModel::getModel),
			Map.entry(SiClassTypeInfoModel.ID_STRING, SiClassTypeInfoModel::getModel),
			Map.entry(VmiClassTypeInfoModel.ID_STRING, VmiClassTypeInfoModel::getModel),
			Map.entry(TypeInfoModel.ID_STRING, TypeInfoModel::getModel),
			Map.entry(IosFailTypeInfoModel.ID_STRING, IosFailTypeInfoModel::getModel)
		);

    /**
     * Get the TypeInfo in the buffer.
     * @param buf
     * @return the TypeInfo at the buffers address.
     * @throws InvalidDataTypeException 
     */
    public static TypeInfo getTypeInfo(MemBuffer buf) throws InvalidDataTypeException {
        return getTypeInfo(buf.getMemory().getProgram(), buf.getAddress());
    }

    /**
     * Get the TypeInfo at the address
     * @param program
     * @param address
     * @return the TypeInfo at the specified address in the specified program
     * or null if none exists.
     */
    public static TypeInfo getTypeInfo(Program program, Address address) {
            String baseTypeName = TypeInfoUtils.getIDString(program, address);
            if (!COPY_MAP.containsKey(baseTypeName)) {
                // invalid typeinfo
                return null;
            } try {
				return COPY_MAP.get(baseTypeName).apply(program, address);
            } catch (Exception e) {
                Msg.error(TypeInfoFactory.class, "Unknown Exception", e);
                return null;
            }
    }

    /**
     * Checks if a valid TypeInfo is located at the start of the buffer
     * @param buf
     * @return true if the buffer contains a valid TypeInfo
     */
    public static boolean isTypeInfo(MemBuffer buf) {
        return buf != null ? isTypeInfo(buf.getMemory().getProgram(), buf.getAddress()) : false;
    }

    /**
     * Checks if a valid TypeInfo is located at the address in the program.
     * @param program
     * @param address
     * @return true if the buffer contains a valid TypeInfo
     */
    public static boolean isTypeInfo(Program program, Address address) {
        try {
            return COPY_MAP.containsKey(TypeInfoUtils.getIDString(program, address));
        } catch (AddressOutOfBoundsException e) {
            return false;
        }
    }

    /**
     * Invokes getDataType on the TypeInfo containing the specified typename
     * 
     * @param program
     * @param typename
     * @return the TypeInfo structure for the typename
	 * @see TypeInfoModel#getDataType()
     */
    public static Structure getDataType(Program program, String typename) {
        if (COPY_MAP.containsKey(typename)) {
            try {
				for (Class<? extends TypeInfo> type : ClassSearcher.getClasses(TypeInfo.class)) {
					final Field field = type.getDeclaredField(ID_FIELD);
					if (typename.equals((field.get(null)))) {
						Method dataTypeGetter = type.getDeclaredMethod(
							"getDataType", DataTypeManager.class);
						return (Structure) dataTypeGetter.invoke(
							null, program.getDataTypeManager());
					}
				}
            } catch (Exception e) {
                Msg.error(TypeInfoFactory.class, e);
            }
        }
        return null;
	}

}
