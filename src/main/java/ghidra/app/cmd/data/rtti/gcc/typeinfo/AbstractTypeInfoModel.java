package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemangledFunctionReference;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import static ghidra.app.util.demangler.DemanglerUtil.demangle;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.getCxxAbiCategoryPath;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Base Model for Type Info and its derivatives.
 */
public abstract class AbstractTypeInfoModel implements TypeInfo {

    protected static final int BASE_ORDINAL = 0;
    protected boolean isValid;

    protected Program program;
    protected Address address;
    private DataType dataType = null;

    private String typeName = "";
    protected Namespace namespace;
    private MemoryBufferImpl buf;

    protected static final String SUPER = "super_";
    protected static final CategoryPath STD_PATH = new CategoryPath(CategoryPath.ROOT, "std");

    private static final Pattern TYPE_PATTERN = Pattern.compile(".*_\\((.*)\\)");
    private static final Pattern FUNCTION_PATTERN = Pattern.compile("(.*)\\S*?\\((.*)\\)");

    protected AbstractTypeInfoModel() {
        this.isValid = false;
    }

    protected AbstractTypeInfoModel(Program program, Address address) {
    	this.isValid = TypeInfoUtils.getIDString(program, address).equals(getIdentifier());
    	if (isValid) {
	    	this.program = program;
	        this.address = address;
	        this.buf = new MemoryBufferImpl(program.getMemory(), address);
	        this.typeName = TypeInfoUtils.getTypeName(program, address);
	        this.namespace = TypeInfoUtils.getNamespaceFromTypeName(program, typeName);
    	}
    }

    @Override
    public boolean isValid() {
        return isValid;
    }

    /**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    @Override
    public final boolean equals(Object object) {
        if (!(object instanceof TypeInfo)) {
            return false;
        } if (!isValid && !((TypeInfo) object).isValid()) {
            return true;
        }
        return ((TypeInfo) object).getAddress().equals(address);
    }

    /**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    @Override
    public final int hashCode() {
        return typeName.hashCode();
    }

    @Override
    public Namespace getNamespace() {
        return isValid ? namespace : program.getGlobalNamespace();
    }

    protected MemBuffer getBuffer() {
        return isValid ? buf : null;
    }

    protected static DataType alignDataType(StructureDataType struct, DataTypeManager dtm) {
        struct.setInternallyAligned(true);
        struct.adjustInternalAlignment();
        DataType result = dtm.resolve(struct, KEEP_HANDLER);
        return result.getLength() <= 1 ? dtm.resolve(struct, REPLACE_HANDLER) : result;
    }

    @Override
    public final String getName() {
        return isValid ? namespace.getName() : "";
    }

    protected Structure getDataType(String dtName, String description) {
        return getDataType(program.getDataTypeManager(), dtName, description);
    }

    protected static Structure getDataType(DataTypeManager dtm, String name, String description) {
        DataType existingDt = dtm.getDataType(getCxxAbiCategoryPath(), name);
        if (existingDt != null && existingDt.getDescription().equals(description)) {
            return (Structure) existingDt;
        }
        StructureDataType struct = new StructureDataType(getCxxAbiCategoryPath(), name, 0, dtm);
        struct.add(TypeInfoModel.getDataType(dtm), "super_type_info", null);
        struct.setDescription(description);
        return (Structure) alignDataType(struct, dtm);
    }

    @Override
    public Address getAddress() {
        return isValid ? address : Address.NO_ADDRESS;
    }

    @Override
    public String getTypeName() {
        return isValid() ? typeName : "";
    }

    @Override
    public DataType getRepresentedDataType() {
        if(isValid()) {
            if (dataType == null) {
                dataType = parseDataType(typeName);
            }
        } return dataType;
    }

    private static DemangledDataType getDemangledType(String demangled) {
        if (demangled.contains(DemangledDataType.UNSIGNED)) {
            demangled = demangled.replace(DemangledDataType.UNSIGNED+" ", "u");
        }
        if (demangled.contains(" ")) {
            int index = demangled.indexOf(" ");
            demangled = demangled.substring(0, index);
        }
        return new DemangledDataType(demangled);
    }

    protected DemangledFunctionReference getDemangledFunction(String signature) {
        DemangledFunctionReference method = new DemangledFunctionReference();
        Matcher matcher = FUNCTION_PATTERN.matcher(signature);
        if (matcher.matches()) {
            method.setReturnType(getDemangledType(matcher.group(1)));
            String[] parameters = matcher.group(2).split(",");
            for (String parameter : parameters) {
                if (parameter.equals("")) {
                    parameter = DemangledDataType.VOID;
                }
                method.addParameter(getDemangledType(parameter));
            }
        }
        return method;
    }

    protected DataType parseDataType(String dataTypeName) {
        DemangledObject demangled = demangle("_Z1_"+dataTypeName);
        if (demangled != null) {
            Matcher matcher = TYPE_PATTERN.matcher(demangled.getSignature(false));
            if (matcher.matches()) {
                DataTypeManager dtm = program.getDataTypeManager();
                if (matcher.group(1).contains("(")) {
                    // we have a demangled function
                    DemangledFunctionReference method = getDemangledFunction(matcher.group(1));
                    return ((Pointer) method.getDataType(dtm)).getDataType();
                }
                DemangledDataType dt = new DemangledDataType(matcher.group(1));
                return dt.getDataType(dtm);
            }
        } return null;
    }
}