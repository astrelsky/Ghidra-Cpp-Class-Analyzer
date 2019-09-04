package ghidra.app.cmd.data.rtti.gcc.factory;

import java.util.Map;
import java.util.Map.Entry;
import java.util.AbstractMap;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;

public class TypeInfoFactory {

    // for error logging
    private static final TypeInfoFactory THIS = new TypeInfoFactory();
    private static final String ID_FIELD = "ID_STRING";

    private TypeInfoFactory() {}

    private static final Map<String, Class<? extends TypeInfo>> COPY_MAP = getMap();

    private static Map<String, Class<? extends TypeInfo>> getMap() {
        try {
            return Map.ofEntries(
                getEntry(ArrayTypeInfoModel.class),
                getEntry(ClassTypeInfoModel.class),
                getEntry(EnumTypeInfoModel.class),
                getEntry(FunctionTypeInfoModel.class),
                getEntry(FundamentalTypeInfoModel.class),
                getEntry(PBaseTypeInfoModel.class),
                getEntry(PointerToMemberTypeInfoModel.class),
                getEntry(PointerTypeInfoModel.class),
                getEntry(SiClassTypeInfoModel.class),
                getEntry(VmiClassTypeInfoModel.class),
                getEntry(TypeInfoModel.class),
                getEntry(IosFailTypeInfoModel.class)
            );
        } catch (Exception e) {
            Msg.error(THIS, e);
            return null;
        }
    }

    private static Entry<String, Class<? extends TypeInfo>> getEntry(
        Class<? extends TypeInfo> type) throws Exception {
            String key = (String) type.getField(ID_FIELD).get(null);
            return new AbstractMap.SimpleEntry<>(key, type);
        }

    private static Constructor<? extends TypeInfo> getConstructor(Class<? extends TypeInfo> type)
        throws NoSuchMethodException {
            return type.getConstructor(Program.class, Address.class);
    }

    /**
     * Get the TypeInfo in the buffer.
     * @param buf
     * @return the TypeInfo at the buffers address
     */
    public static TypeInfo getTypeInfo(MemBuffer buf) {
        return getTypeInfo(buf.getMemory().getProgram(), buf.getAddress());
    }

    /**
     * Get the TypeInfo at the address
     * @param program
     * @param address
     * @return the TypeInfo at the specified address in the specified program
     */
    public static TypeInfo getTypeInfo(Program program, Address address) {
        String baseTypeName = TypeInfoUtils.getIDString(program, address);
        if (!COPY_MAP.containsKey(baseTypeName)) {
            return TypeInfo.INVALID;
        } try {
            Constructor<?> cloneContainer = getConstructor(COPY_MAP.get(baseTypeName));
            return (TypeInfo) cloneContainer.newInstance(program, address);
        } catch (Exception e) {
            Msg.error(THIS, "Unknown Exception", e);
            return TypeInfo.INVALID;
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
     * @param Program
     * @param Address
     * @return true if the buffer contains a valid TypeInfo
     */
    public static boolean isTypeInfo(Program program, Address address) {
        try {
            return COPY_MAP.containsKey(TypeInfoUtils.getIDString(program, address));
        } catch (AddressOutOfBoundsException e) {
            return false;
        }
    }

    public static DataType getDataType(Program program, String typename) {
        if (COPY_MAP.containsKey(typename)) {
            try {
                Method dataTypeGetter = COPY_MAP.get(typename).getDeclaredMethod(
                    "getDataType", DataTypeManager.class);
                return (DataType) dataTypeGetter.invoke(null, program.getDataTypeManager());
            } catch (Exception e) {
                Msg.error(THIS, e);
            }
        }
        return null;
    }
}
