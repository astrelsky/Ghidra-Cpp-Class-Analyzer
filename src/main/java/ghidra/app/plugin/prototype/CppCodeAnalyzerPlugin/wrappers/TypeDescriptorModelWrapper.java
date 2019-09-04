package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers;

import java.util.*;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.Vftable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.inheritClass;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class TypeDescriptorModelWrapper extends TypeDescriptorModel implements ClassTypeInfo {

    private static final String PURE_VIRTUAL_FUNCTION_NAME = "_purecall";

    private static final String SYMBOL_NAME = "RTTI_Complete_Object_Locator";

    private static final String SUPER = "super_";
    private static final String VFTABLE = "vftable";

    private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

    private ClassTypeInfo[] parents;
    private Rtti1Model[] rtti1Models;
    private Rtti2Model rtti2Model;
    private Rtti3Model rtti3Model;
    private List<Rtti4Model> rtti4Models;
    private Vftable vtable;
    private List<Rtti1Model> virtualModels;
    private SymbolTable sTable;
    private Map<Rtti1Model, Rtti4Model> virtualMetaData;

    public TypeDescriptorModelWrapper(Program program, Address address) {
        super(program, address, DEFAULT_OPTIONS);
        this.sTable = program.getSymbolTable();
        try {
            setupRtti4Models();
            if (!rtti4Models.isEmpty()) {
                this.rtti3Model = rtti4Models.get(0).getRtti3Model();
                this.rtti2Model = rtti3Model.getRtti2Model();
                getRtti1Models();
            }
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
    }

    private void setupRtti4Models() {
        rtti4Models = new ArrayList<>();
        for (Symbol symbol : sTable.getSymbols(getDescriptorAsNamespace())) {
            if (!symbol.getName().contains(SYMBOL_NAME)) {
                continue;
            }
            Rtti4Model model = new Rtti4Model(getProgram(), symbol.getAddress(), DEFAULT_OPTIONS);
            try {
                model.validate();
                rtti4Models.add(model);
            } catch (InvalidDataTypeException e) {
                Msg.error(this, e);
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof TypeDescriptorModelWrapper) {
            return getAddress().equals(((TypeDescriptorModelWrapper) o).getAddress());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return getAddress().hashCode();
    }

    @Override
    public String getName() {
        return getDescriptorName();
    }

    @Override
    public Namespace getNamespace() {
        return getDescriptorAsNamespace();
    }

    @Override
    public String getTypeName() {
        try {
            return super.getTypeName();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
            return "";
        }
    }

    @Override
    public String getIdentifier() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isValid() {
        try {
            if (rtti1Models == null) {
                return false;
            }
            validate();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public GhidraClass getGhidraClass() {
        Namespace namespace = getNamespace();
        if (!(namespace instanceof GhidraClass)) {
            try {
                namespace = NamespaceUtils.convertNamespaceToClass(namespace);
            } catch (InvalidInputException e) {
                Msg.error(this, e);
                return null;
            }
        } return (GhidraClass) namespace;
    }

    @Override
    public boolean hasParent() {
        return getRtti1Models().length > 0;
    }

    private Set<Rtti1Model> getNonVirtualRtti1() {
        Set<Rtti1Model> nonVirtuals = new HashSet<>(rtti1Models.length);
        for (Rtti1Model model : rtti1Models) {
            if (!isVirtual(model)) {
                nonVirtuals.add(model);
            }
        }
        return nonVirtuals;
    }

    private Set<Rtti1Model> getVirtualModels() {
        return virtualMetaData.keySet();
    }

    private Rtti1Model[] getRtti1Models() {
        try {
            if (rtti1Models == null) {
                if (rtti2Model == null) {
                    getRtti2Model();
                }
                int baseCount = rtti3Model.getRtti1Count();
                Set<String> vModels = new HashSet<>();
                virtualModels = new ArrayList<>();
                List<Rtti1Model> modelList = new ArrayList<>(baseCount);

                for (int i = 1; i < baseCount; i++) {
                    Rtti1Model model = rtti2Model.getRtti1Model(i);
                    if (isVirtual(model)) {
                        String name = model.getRtti0Model().getDescriptorName();
                        if (!vModels.contains(name)) {
                            TypeDescriptorModelWrapper parent = upcastRtti1(model);
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
                rtti1Models = modelList.toArray(new Rtti1Model[modelList.size()]);
                virtualMetaData = new HashMap<>(virtualModels.size());
                List<Address> vfTableAddresses = getVftableAddresses();
                Collections.reverse(vfTableAddresses);
                Collections.reverse(virtualModels);
                for (int i = 0; i < virtualModels.size(); i++) {
                    Address metaAddress = vfTableAddresses.get(i).subtract(getDefaultPointerSize());
                    Address rtti4Address = getAbsoluteAddress(getProgram(), metaAddress);
                    Rtti4Model model = new Rtti4Model(getProgram(), rtti4Address, DEFAULT_OPTIONS);
                    try {
                        model.validate();
                    } catch (InvalidDataTypeException e) {
                        metaAddress.toString();
                    }
                    virtualMetaData.put(virtualModels.get(i), model);
                }
            }
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
        return rtti1Models;
    }

    private Rtti2Model getRtti2Model() {
        try {
            if (rtti2Model == null) {
                rtti2Model = rtti3Model.getRtti2Model();
            }
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
        return rtti2Model;
    }

    private TypeDescriptorModelWrapper upcastRtti1(Rtti1Model model) {
        try {
            return new TypeDescriptorModelWrapper(getProgram(), model.getRtti0Address());
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
            return null;
        }
    }

    @Override
    public ClassTypeInfo[] getParentModels() {
        if (parents == null) {
            Set<Rtti1Model> types = new LinkedHashSet<>(Arrays.asList(rtti1Models));
            for (int i = 0; i < rtti1Models.length; i++) {
                TypeDescriptorModelWrapper parent = upcastRtti1(rtti1Models[i]);
                types.removeAll(parent.getNonVirtualRtti1());
            }
            parents = new ClassTypeInfo[types.size()];
            Iterator<Rtti1Model> models = types.iterator();
            int i = 0;
            while(models.hasNext()) {
                parents[i++] = upcastRtti1(models.next());
            }
        }
        return parents;
    }

    @Override
    public Vftable getVtable() {
        try {
            return getVtable(null);
        } catch (CancelledException e) {
            return null;
        }
    }

    @Override
    public Vftable getVtable(TaskMonitor monitor) throws CancelledException {
        try {
            if (vtable == null) {
                vtable =
                    new WindowsVtableModel(getProgram(), getVftableAddresses(),
                                           getParentModels(), this);
            }
        } catch (Exception e) {
            Msg.error(this, e);
            vtable = Vftable.INVALID;
        }
        return vtable;
    }

    private List<Address> getVftableAddresses() {
        List<Address> tableAddresses = new ArrayList<>();
        for (Symbol symbol : sTable.getSymbols(getDescriptorAsNamespace())) {
            if (symbol.getName().contains(VFTABLE)) {
                if (symbol.getName().contains("meta_ptr")) {
                    continue;
                }
                tableAddresses.add(symbol.getAddress());
            }
        }
        tableAddresses.sort(null);
        return tableAddresses;
    }

    private boolean isVirtual(Rtti1Model model) {
        try {
            return (model.getAttributes() >> 4 & 1) == 1;
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
            return false;
        }
    }

    private int getOffset(Rtti1Model model) {
        try {
            if (isVirtual(model)) {
                return virtualMetaData.get(model).getVbTableOffset();
            }
            return model.getMDisp();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
        return -1;
    }

    private int getFirstVirtualOffset() {
        for (Rtti1Model model : rtti1Models) {
            if (virtualMetaData.containsKey(model)) {
                return getOffset(model);
            }
        }
        return -1;
    }

    private Structure getSuperClassDataType() {
        if (virtualMetaData.isEmpty()) {
            return getClassDataType();
        }
        int vOffset = getFirstVirtualOffset();
        CategoryPath path = getClassDataType().getCategoryPath();
        Structure struct = new StructureDataType(path, SUPER+getName(), 0, getDataTypeManager());
        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            if (comp.getOffset() >= vOffset) {
                break;
            }
            struct.insertAtOffset(comp.getOrdinal(), comp.getDataType(), comp.getLength(),
                                  comp.getFieldName(), comp.getComment());
        }
        return resolve(struct);
    }

    private Structure resolve(Structure struct) {
        return (Structure) getDataTypeManager().resolve(
            struct, DataTypeConflictHandler.REPLACE_HANDLER);
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
	public Structure getClassDataType(boolean repopulate) {
        Structure struct = ClassTypeInfoUtils.getPlaceholderStruct(this, getDataTypeManager());
        for (Rtti1Model model : rtti1Models) {
            if (shouldIgnore(model)) {
                continue;
            }
            TypeDescriptorModelWrapper parent = upcastRtti1(model);
            Structure parentStruct = parent.getSuperClassDataType();
            inheritClass(struct, parentStruct, getOffset(model));
        }
        return resolve(struct);
    }

	@Override
	public String getUniqueTypeName() {
        try {
            List<String> names = getRtti2Model().getBaseClassTypes();
            StringBuffer buffer = new StringBuffer();
            for (String name : names) {
                buffer.append(name);
            }
            return buffer.toString();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
            return "";
        }
	}

    @Override
    public boolean isAbstract() {
        for (Function[] functionTable : getVtable().getFunctionTables()) {
            for (Function function : functionTable) {
                if (function != null) {
                    if (function.getName().equals(PURE_VIRTUAL_FUNCTION_NAME)) {
                        return true;
                    }
                } else {
                    // only occure with relocation which is only valid for _pure_call
                    return true;
                }
            }
        }
        return false;
    }
}
