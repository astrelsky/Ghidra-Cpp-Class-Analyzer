package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

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
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ImageBaseOffset32DataType;
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
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getReferencedAddress;

public final class RttiModelWrapper implements ClassTypeInfo {

	private static final String LOCATOR_SYMBOL_NAME = "RTTI_Complete_Object_Locator";
    private static final String PURE_VIRTUAL_FUNCTION_NAME = "_purecall";
	private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();
	private static final Pattern PATTERN = Pattern.compile("vftable(?!_meta_ptr)");

    private final TypeDescriptorModel type;
    private List<Rtti1Model> bases;
    private final Rtti2Model baseArray;
    private final Rtti3Model hierarchyDescriptor;
    private final Vtable vtable;
    private final ClassTypeInfo[] parents;
	private final Rtti1Model baseModel;
	private final VsCppClassBuilder builder;
	private final String typeName;
	private final List<String> baseTypes;
	private final Set<ClassTypeInfo> virtualParents;
	private final Map<ClassTypeInfo, Integer> baseOffsets;

	private RttiModelWrapper(Rtti1Model model) throws InvalidDataTypeException {
		this.baseModel = model;
		final Program program = model.getProgram();
		this.type = model.getRtti0Model();
		this.hierarchyDescriptor =
			new Rtti3Model(program, model.getRtti3Address(), DEFAULT_OPTIONS);
		this.baseArray = hierarchyDescriptor.getRtti2Model();
		this.parents = doGetParentModels();
		this.vtable = doGetVtable();
		this.builder = new VsCppClassBuilder(this);
		this.typeName = type.getTypeName();
		this.baseTypes = baseArray.getBaseClassTypes();
		this.virtualParents = doGetVirtualParents();
		this.baseOffsets = doGetBaseOffsets();
	}

	private static ClassTypeInfo wrapNoExcept(Rtti1Model model) {
		// models must have already been checked
		try {
			return new RttiModelWrapper(model);
		} catch (InvalidDataTypeException e) {
			Msg.error(RttiModelWrapper.class, model.getAddress().toString(), e);
		}
		return new RttiModelWrapper();
	}

	private RttiModelWrapper() {
		// This should never ever be reached
		Msg.error(this, new Throwable("Dummy Constructor Reached"));
		this.type = null;
		this.hierarchyDescriptor = null;
		this.baseArray = null;
		this.parents = null;
		this.vtable = null;
		this.builder = null;
		this.baseModel = null;
		this.typeName = null;
		this.baseTypes = null;
		this.virtualParents = null;
		this.baseOffsets = null;
	}

    public static RttiModelWrapper getWrapper(TypeDescriptorModel typeModel) {
		try {
			return new RttiModelWrapper(typeModel);
		} catch (InvalidDataTypeException e) {
			return null;
		}
	}

	private RttiModelWrapper(TypeDescriptorModel typeModel) throws InvalidDataTypeException {
		Rtti1Model base = null;
		Rtti3Model model = null;
		Rtti2Model rtti2Model = null;
		ClassTypeInfo[] parentModels = null;
		model = getRtti3Model(typeModel);
		if (model != null) {
			typeModel = model.getRtti0Model();
			typeModel.validate();
			rtti2Model = model.getRtti2Model();
			rtti2Model.validate();
			base = rtti2Model.getRtti1Model(0);
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
		}
		this.type = typeModel;
		this.hierarchyDescriptor = model;
		this.baseArray = rtti2Model;
		this.baseModel = base;
		isSetupComplete();
		parentModels = doGetParentModels();
		this.parents = parentModels;
		this.vtable = doGetVtable();
		builder = new VsCppClassBuilder(this);
		this.typeName = type.getTypeName();
		this.baseTypes = baseArray.getBaseClassTypes();
		this.virtualParents = doGetVirtualParents();
		this.baseOffsets = doGetBaseOffsets();
	}

	Rtti1Model getBaseModel() {
		return baseModel;
	}

	private void isSetupComplete() throws InvalidDataTypeException {
		if (type == null || hierarchyDescriptor == null || baseArray == null) {
			throw new InvalidDataTypeException();
		}
	}

	private static Rtti3Model getRtti3Model(TypeDescriptorModel model) {
		final Rtti4Model rtti4Model = getRtti4Model(model);
		if (rtti4Model != null) {
			try {
				return rtti4Model.getRtti3Model();
			} catch (InvalidDataTypeException e) {
				// already checked for validity.
			}
		}
		final Program program = model.getProgram();
		final Address addr = model.getAddress();
		int alignment = new ImageBaseOffset32DataType(program.getDataTypeManager()).getAlignment();
		ReferenceFilter filter = new ReferenceFilter(program);
		try {
			Stream<Address> addresses = ProgramMemoryUtil
				.findImageBaseOffsets32(program, alignment, addr, TaskMonitor.DUMMY)
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
		} catch (CancelledException e) {
			// no problem
		}
		return null;
	}

	private static boolean filterSymbols(Symbol symbol) {
		return symbol.getName().contains(LOCATOR_SYMBOL_NAME);
	}

	private static Rtti4Model getRtti4Model(TypeDescriptorModel model) {
        SymbolTable table = model.getProgram().getSymbolTable();
        Namespace ns = model.getDescriptorAsNamespace();
        if (ns == null) {
            Symbol symbol = table.getPrimarySymbol(model.getAddress());
            ns = symbol.getParentNamespace();
        }
        if (ns != null && !ns.isGlobal()) {
			Stream<Symbol> symbols =
				StreamSupport.stream(table.getSymbols(ns).spliterator(), false)
							 .filter(RttiModelWrapper::filterSymbols);
            for (Symbol symbol : (Iterable<Symbol>) () -> symbols.iterator()) {
                if (symbol.getName().contains(LOCATOR_SYMBOL_NAME)) {
                    Rtti4Model locatorModel = new Rtti4Model(
						model.getProgram(), symbol.getAddress(), DEFAULT_OPTIONS);
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
            return getUniqueTypeName().equals(((RttiModelWrapper) o).getUniqueTypeName());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return getUniqueTypeName().hashCode();
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
    public String getTypeName() {
        return typeName;
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
		// the first one is our typename
		return baseTypes.size() > 1;
	}

	private static boolean vftableSymbolFilter(Symbol t) {
		return PATTERN.matcher(t.getName()).matches();
	}

    private List<Address> getVftableAddresses() {
		final SymbolTable table = type.getProgram().getSymbolTable();
		return StreamSupport.stream(
			table.getSymbols(type.getDescriptorAsNamespace()).spliterator(), false)
				 .filter(RttiModelWrapper::vftableSymbolFilter)
				 .map(Symbol::getAddress)
				 .sorted()
				 .collect(Collectors.toList());
	}

	@Override
	public ClassTypeInfo[] getParentModels() {
		return parents;
	}

	private static List<Rtti1Model> getRtti1Models(Program program, Address addr, int count) {
		final List<Rtti1Model> result = new ArrayList<>(count-1);
		final int size = 4;
		Address currentAddr = addr.add(size);
		for (int i = 1; i < count; i++) {
			// start at 1 since the first base is this
			final Address address = getReferencedAddress(program, currentAddr);
			Rtti1Model model = new Rtti1Model(program, address, DEFAULT_OPTIONS);
			try {
				model.validate();
				result.add(model);
			} catch (InvalidDataTypeException e) {
				Msg.error(RttiModelWrapper.class, address.toString(), e);
			}
			currentAddr = currentAddr.add(size);
		}
		return result;
	}

	private ClassTypeInfo[] doGetParentModels() {
		final Program program = type.getProgram();
		Address addr = hierarchyDescriptor.getAddress();
		final int baseCount = Rtti3Model.getRtti1Count(program, addr);
		bases = new ArrayList<>(baseCount);
		for (Rtti1Model model : getRtti1Models(program, baseArray.getAddress(), baseCount)) {
			if (!shouldIgnore(model)) {
				bases.add(model);
			}
		}
		return bases.stream()
					.map(RttiModelWrapper::wrapNoExcept)
					.toArray(size -> new ClassTypeInfo[size]);
	}

    static boolean isVirtual(Rtti1Model model) throws InvalidDataTypeException {
        return (model.getAttributes() >> 4 & 1) == 1;
	}

    @Override
    public boolean isAbstract() {
        for (Function[] table : getVtable().getFunctionTables()) {
            for (Function function : table) {
                if (function.getName().contains(PURE_VIRTUAL_FUNCTION_NAME)) {
                    return true;
                }
            }
        }
        return false;
	}

	private Vtable doGetVtable() {
		final List<Address> addresses = getVftableAddresses();
		if (!addresses.isEmpty()) {
			return new WindowsVtableModel(type.getProgram(), getVftableAddresses(), this);
		}
		return Vtable.NO_VTABLE;
	}

    @Override
    public Vtable getVtable(TaskMonitor monitor) throws CancelledException {
        return vtable;
	}

	private int getVirtualOffset(Rtti1Model model) {
		if (Vtable.isValid(vtable)) {
			try {
				return ((WindowsVtableModel) vtable).getVirtualOffset(model);
			} catch (InvalidDataTypeException e) {
				// return -1
			}
		}
		return -1;
	}

    private int getOffset(Rtti1Model model) {
        try {
            if (isVirtual(model)) {
				final int pDisp = model.getPDisp();
				final int vDisp = getVirtualOffset(model);
				if (vDisp > 0 && pDisp >= 0) {
					return vDisp + pDisp;
				}
				if (vDisp > 0) {
					return vDisp;
				}
				Msg.warn(this, "Missing offset for: " + model.getRtti0Model().getTypeName());
				return -1;
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
    public String getUniqueTypeName() {

        StringBuilder builder = new StringBuilder();
        for (String name : baseTypes) {
            builder.append(name);
        }
        return builder.toString();
	}

	@Override
    public Set<ClassTypeInfo> getVirtualParents() {
        return virtualParents;
    }

    private Set<ClassTypeInfo> doGetVirtualParents() throws InvalidDataTypeException {
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
        return baseOffsets;
	}

	private Map<ClassTypeInfo, Integer> doGetBaseOffsets() throws InvalidDataTypeException {
        Map<ClassTypeInfo, Integer> map = new HashMap<>(bases.size());
        for (Rtti1Model base : bases) {
            if (!shouldIgnore(base)) {
				map.put(new RttiModelWrapper(base), getOffset(base));
            }
        }
        return map;
    }

    @Override
    public Structure getClassDataType() {
		final Structure structure = builder.getDataType();
		return structure;
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
