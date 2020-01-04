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
import java.util.function.Predicate;
import java.util.stream.Stream;

import ghidra.app.cmd.data.CreateTypeDescriptorBackgroundCmd;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.CreateRtti2BackgroundCmd;
import ghidra.app.cmd.data.rtti.CreateRtti3BackgroundCmd;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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

    private final TypeDescriptorModel type;
    private List<Rtti1Model> bases;
    private final Rtti2Model baseArray;
    private final Rtti3Model hierarchyDescriptor;
    private final Rtti4Model objectLocator;
    private WindowsVtableModel vtable;
    private final ClassTypeInfo[] parents;
    private Map<Rtti1Model, Rtti4Model> virtualMetaData;
	private final VsCppClassBuilder builder;
	
	private RttiModelWrapper(Rtti1Model model) throws InvalidDataTypeException {
		final Program program = model.getProgram();
		this.type = model.getRtti0Model();
		this.hierarchyDescriptor =
			new Rtti3Model(program, model.getRtti3Address(), DEFAULT_OPTIONS);
		this.baseArray = hierarchyDescriptor.getRtti2Model();
		this.objectLocator = getRtti4Model(type);
		this.parents = doGetParentModels();
		this.builder = new VsCppClassBuilder(this);
	}

    public RttiModelWrapper(TypeDescriptorModel typeModel) {
		Rtti3Model model = null;
		Rtti2Model rtti2Model = null;
		Rtti4Model rtti4Model = null;
		ClassTypeInfo[] parentModels = null;
		try {
			rtti4Model = getRtti4Model(typeModel);
			if (rtti4Model != null) {
				rtti4Model.validate();
			} else {
				model = getRtti3Model(typeModel);
			}
		} catch (InvalidDataTypeException e) {
			// it doesn't exist. carry on
		}
		try {
			if (rtti4Model == null && model != null) {
				typeModel = model.getRtti0Model();
				typeModel.validate();
				rtti2Model = model.getRtti2Model();
				rtti2Model.validate();
				/* If we've reached here it is then the windows RTTI Analyzer
				   did not find and create rtti2 and rtti3 models. */
				final Program program = typeModel.getProgram();
				final DataApplyOptions applyOptions = new DataApplyOptions();
				BackgroundCommand cmd =
					new CreateTypeDescriptorBackgroundCmd(typeModel, applyOptions);
				cmd.applyTo(program, TaskMonitor.DUMMY);
				cmd = new CreateRtti2BackgroundCmd(
					rtti2Model.getAddress(), model.getRtti1Count(),
					DEFAULT_OPTIONS, applyOptions);
				cmd.applyTo(program, TaskMonitor.DUMMY);
				cmd = new CreateRtti3BackgroundCmd(
					model.getAddress(), DEFAULT_OPTIONS, applyOptions);
				cmd.applyTo(program, TaskMonitor.DUMMY);
			} else if (rtti4Model != null) {
				// use the ClassHierarchyDescriptor from rtti4 if available
				typeModel = rtti4Model.getRtti0Model();
				typeModel.validate();
				model = rtti4Model.getRtti3Model();
				model.validate();
				rtti2Model = model.getRtti2Model();
			}
		} catch (InvalidDataTypeException e) {
			Msg.error(this, "Input model invalid", e);
		}
		this.type = typeModel;
		this.objectLocator = rtti4Model;
		this.hierarchyDescriptor = model;
		this.baseArray = rtti2Model;
		if (isSetupComplete()) {
			parentModels = doGetParentModels();
			this.parents = parentModels;
			builder = new VsCppClassBuilder(this);
		} else {
			this.parents = parentModels;
			builder = null;
		}
	}

	private boolean isSetupComplete() {
		return type != null && hierarchyDescriptor != null && baseArray != null;
	}

	private static Rtti3Model getRtti3Model(TypeDescriptorModel model) {
		final Program program = model.getProgram();
		final Address addr = model.getAddress();
		ReferenceFilter filter = new ReferenceFilter(program);
		Stream<Address> addresses = GnuUtils.getDirectDataReferences(program, addr)
											.stream()
											.filter(filter);
		for (Address address : (Iterable<Address>) () -> addresses.iterator()) {
			Rtti1Model baseDescriptor = new Rtti1Model(program, address, DEFAULT_OPTIONS);
			try {
				baseDescriptor.validate();
				final Address rtti3Addr = baseDescriptor.getRtti3Address();
				Rtti3Model result = new Rtti3Model(program, rtti3Addr, DEFAULT_OPTIONS);
				result.validate();
				return result;
			} catch (InvalidDataTypeException e) {
				// continue searching
			}
		}
		return null;
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
		validate();
		return parents;
	}

    public ClassTypeInfo[] doGetParentModels() {
            int baseCount;
			try {
				baseCount = hierarchyDescriptor.getRtti1Count();
			}
			catch (InvalidDataTypeException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				baseCount = 0;
			}
            Set<String> vModels = new HashSet<>();
            List<Rtti1Model> virtualModels = new ArrayList<>();
            List<Rtti1Model> modelList = new ArrayList<>(baseCount);

			try {
				for (int i = 1; i < baseCount; i++) {
					Rtti1Model model = baseArray.getRtti1Model(i);
					if (isVirtual(model)) {
						String name = model.getRtti0Model().getDescriptorName();
						if (!vModels.contains(name)) {
							try {
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
							} catch (InvalidDataTypeException e) {
								Msg.error(this, model.getRtti0Model().getTypeName());
							}
						}
					} else {
						modelList.add(model);
					}
				}
			} catch (InvalidDataTypeException e) {
				Msg.error(this, e);
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
        ClassTypeInfo[] result = new ClassTypeInfo[bases.size()];
        for (int i = 0; i < bases.size(); i++) {
			try {
				result[i] = new RttiModelWrapper(bases.get(i));
			} catch (Exception e) {
				Msg.error(this, e);
			}
        }
        return result;
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

    protected Map<ClassTypeInfo, Integer> getBaseOffsets() throws InvalidDataTypeException {
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

	private static class ReferenceFilter implements Predicate<Address> {

		private final Listing listing;
		private ReferenceFilter(Program program) {
			this.listing = program.getListing();
		}
	
		@Override
		public boolean test(Address t) {
			final Data data = listing.getDataContaining(t);
			if (data != null) {
				return !data.getDataType().getName().contains(EHCatchHandlerModel.DATA_TYPE_NAME);
			}
			return true;
		}
	}
}
