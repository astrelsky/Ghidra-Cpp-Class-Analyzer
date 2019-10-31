package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class RttiModelWrapper implements ClassTypeInfo {

    private static final String LOCATOR_SYMBOL_NAME = "RTTI_Complete_Object_Locator";
    private static final String META_PTR = "meta_ptr";
    private static final String VFTABLE = "vftable";
    private static final String PURE_VIRTUAL_FUNCTION_NAME = "_purecall";
    private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

    private TypeDescriptorModel type;
    private List<Rtti1Model> bases;
    private Rtti2Model baseArray;
    private Rtti3Model hierarchyDescriptor;
    private Rtti4Model objectLocator;
    private WindowsVtableModel vtable;
    private ClassTypeInfo[] parents;
    private Map<Rtti1Model, Rtti4Model> virtualMetaData;
    private VsCppClassBuilder builder;

    public RttiModelWrapper(TypeDescriptorModel model) {
        this(getRtti4Model(model));
    }

    public RttiModelWrapper(Rtti1Model model) {
        this(model.getRtti0Model());
    }

    public RttiModelWrapper(Rtti4Model model) {
        if (model != null) {
            try {
                this.objectLocator = model;
                this.type = objectLocator.getRtti0Model();
                this.hierarchyDescriptor = objectLocator.getRtti3Model();
                this.baseArray = hierarchyDescriptor.getRtti2Model();
                this.parents = getParentModels();
                builder = new VsCppClassBuilder(this);
            } catch (InvalidDataTypeException e) {
                Msg.error(this, "Input model invalid");
            }
        }
    }

    private static Rtti4Model getRtti4Model(TypeDescriptorModel model) {
        SymbolTable table = model.getProgram().getSymbolTable();
        Namespace ns = model.getDescriptorAsNamespace();
        if (ns == null) {
            Symbol symbol = table.getPrimarySymbol(model.getAddress());
            ns = symbol.getParentNamespace();
        }
        if (ns != null && !ns.isGlobal()) {
            for (Symbol symbol : table.getSymbols(ns)) {
                if (symbol.getName().contains(LOCATOR_SYMBOL_NAME)) {
                    Rtti4Model locatorModel = new Rtti4Model(model.getProgram(), symbol.getAddress(), DEFAULT_OPTIONS);
                    try {
                        locatorModel.validate();
                        return locatorModel;
                    } catch (InvalidDataTypeException e) {
                    }
                }
            }
        }
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof RttiModelWrapper) {
            try {
                return getUniqueTypeName().equals(((RttiModelWrapper) o).getUniqueTypeName());
            } catch (InvalidDataTypeException e) {
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        try {
            return getUniqueTypeName().hashCode();
        } catch (InvalidDataTypeException e) {
            return super.hashCode();
        }
    }

    @Override
    public String getName() {
        return getNamespace().getName();
    }

    @Override
    public Namespace getNamespace() {
        return type.getDescriptorAsNamespace();
    }

    @Override
    public String getTypeName() throws InvalidDataTypeException {
        return type.getTypeName();
    }

    @Override
    public String getIdentifier() {
        return RttiAnalyzer.TYPE_INFO_STRING;
    }

    @Override
    public DataType getDataType() {
        return null;
    }

    @Override
    public Address getAddress() {
        return type.getAddress();
    }

    @Override
    public void validate() throws InvalidDataTypeException {
        if (objectLocator == null || type == null || hierarchyDescriptor == null || baseArray == null) {
            throw new InvalidDataTypeException("Invalid ClassTypeInfo");
        }
        type.validate();
    }

    @Override
    public GhidraClass getGhidraClass() {
        if (getNamespace() instanceof GhidraClass) {
            return (GhidraClass) getNamespace();
        }
        try {
            return NamespaceUtils.convertNamespaceToClass(getNamespace());
        } catch (InvalidInputException e) {
            Msg.error(this, e);
        }
        return null;
    }

    @Override
    public boolean hasParent() {
        try {
            return hierarchyDescriptor.getRtti1Count() > 1;
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
        return false;
    }

    private Set<Rtti1Model> getVirtualModels() throws InvalidDataTypeException {
        int baseCount = hierarchyDescriptor.getRtti1Count();
        Set<Rtti1Model> result = new HashSet<>(baseCount);
        for (int i = 1; i < baseCount; i++) {
            if (isVirtual(baseArray.getRtti1Model(i))) {
                result.add(baseArray.getRtti1Model(i));
            }
        }
        return result;
    }

    private List<Address> getVftableAddresses() {
        List<Address> tableAddresses = new ArrayList<>();
        SymbolTable table = type.getProgram().getSymbolTable();
        for (Symbol symbol : table.getSymbols(type.getDescriptorAsNamespace())) {
            if (symbol.getName().contains(VFTABLE)) {
                if (symbol.getName().contains(META_PTR)) {
                    continue;
                }
                tableAddresses.add(symbol.getAddress());
            }
        }
        tableAddresses.sort(null);
        return tableAddresses;
    }

    @Override
    public ClassTypeInfo[] getParentModels() throws InvalidDataTypeException {
        if (parents == null) {
            int baseCount = hierarchyDescriptor.getRtti1Count();
            Set<String> vModels = new HashSet<>();
            List<Rtti1Model> virtualModels = new ArrayList<>();
            List<Rtti1Model> modelList = new ArrayList<>(baseCount);

            for (int i = 1; i < baseCount; i++) {
                Rtti1Model model = baseArray.getRtti1Model(i);
                if (isVirtual(model)) {
                    String name = model.getRtti0Model().getDescriptorName();
                    if (!vModels.contains(name)) {
                        RttiModelWrapper parent = new RttiModelWrapper(model);
                        parent.validate();
                        for (Rtti1Model grandparent : parent.getVirtualModels()) {
                            String grandparentName = grandparent.getRtti0Model().getDescriptorName();
                            if (!vModels.contains(grandparentName)) {
                                virtualModels.add(grandparent);
                                vModels.add(grandparentName);
                            }
                        }
                        virtualModels.add(model);
                        vModels.add(name);
                    }
                } else {
                    modelList.add(model);
                }
            }
            modelList.addAll(virtualModels);
            bases = new ArrayList<>(modelList);
            virtualMetaData = new HashMap<>(virtualModels.size());
            List<Address> vfTableAddresses = getVftableAddresses();
            Collections.reverse(vfTableAddresses);
            Collections.reverse(virtualModels);
            int pointerSize = type.getProgram().getDefaultPointerSize();
            for (int i = 0; i < virtualModels.size(); i++) {
                if (i >= vfTableAddresses.size()) {
                    break;
                }
                Address metaAddress = vfTableAddresses.get(i).subtract(pointerSize);
                Address rtti4Address = getAbsoluteAddress(type.getProgram(), metaAddress);
                Rtti4Model model = new Rtti4Model(type.getProgram(), rtti4Address, DEFAULT_OPTIONS);
                try {
                    model.validate();
                } catch (InvalidDataTypeException e) {
                    metaAddress.toString();
                }
                virtualMetaData.put(virtualModels.get(i), model);
            }
        }
        parents = new ClassTypeInfo[bases.size()];
        for (int i = 0; i < bases.size(); i++) {
            parents[i] = new RttiModelWrapper(bases.get(i));
        }
        return parents;
    }

    private boolean isVirtual(Rtti1Model model) throws InvalidDataTypeException {
        return (model.getAttributes() >> 4 & 1) == 1;
    }

    @Override
    public boolean isAbstract() throws InvalidDataTypeException {
        for (Function[] table : getVtable().getFunctionTables()) {
            for (Function function : table) {
                if (function.getName().contains(PURE_VIRTUAL_FUNCTION_NAME)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public Vtable getVtable(TaskMonitor monitor) throws CancelledException {
        if (vtable == null) {
            vtable = new WindowsVtableModel(type.getProgram(), getVftableAddresses(), this);
        }
        return vtable;
    }

    private int getOffset(Rtti1Model model) {
        try {
            if (isVirtual(model)) {
                if (!virtualMetaData.containsKey(model)) {
                    Msg.info(this, "Missing offset for: " + model.getRtti0Model().getTypeName());
                    return -1;
                }
                return virtualMetaData.get(model).getVbTableOffset();
            }
            return model.getMDisp();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
        return -1;
    }

    private boolean shouldIgnore(Rtti1Model model) {
        try {
            // Not virtual and a repeated base
            return !isVirtual(model) && ((model.getAttributes() & 2) == 2);
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
            return true;
        }
    }

    @Override
    public String getUniqueTypeName() throws InvalidDataTypeException {
        validate();
        List<String> names = baseArray.getBaseClassTypes();
        StringBuffer buffer = new StringBuffer();
        for (String name : names) {
            buffer.append(name);
        }
        return buffer.toString();
    }

    @Override
    public Set<ClassTypeInfo> getVirtualParents() throws InvalidDataTypeException {
        validate();
        Set<ClassTypeInfo> result = new LinkedHashSet<>();
        int baseCount = hierarchyDescriptor.getRtti1Count();
        for (int i = 1; i < baseCount; i++) {
            Rtti1Model model = baseArray.getRtti1Model(i);
            ClassTypeInfo parent = new RttiModelWrapper(model);
            result.addAll(parent.getVirtualParents());
            if (isVirtual(model)) {
                result.add(new RttiModelWrapper(model));
            }
        }
        return result;
    }

    protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
        Map<ClassTypeInfo, Integer> map = new HashMap<>(bases.size());
        for (Rtti1Model base : bases) {
            if (!shouldIgnore(base)) {
                map.put(new RttiModelWrapper(base), getOffset(base));
            }
        }
        return map;
    }

    @Override
    public Structure getClassDataType() throws InvalidDataTypeException {
        return builder.getDataType();
    }
}
