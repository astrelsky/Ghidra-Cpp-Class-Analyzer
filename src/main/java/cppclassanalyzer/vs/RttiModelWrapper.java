package cppclassanalyzer.vs;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.*;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import cppclassanalyzer.vs.RttiModelSearcher.AnyRttiModel;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getReferencedAddress;

public final class RttiModelWrapper implements VsClassTypeInfo {

	private static final String VFTABLE_SYMBOL_NAME = "vftable_meta_ptr";

	private final TypeDescriptorModel type;
	private final Rtti2Model baseArray;
	private final Rtti3Model hierarchyDescriptor;
	private final Rtti4Model completeObjectLocator;
	private final Vtable vtable;
	private final ClassTypeInfo[] parents;
	private final Rtti1Model baseModel;
	private final VsCppClassBuilder builder;
	private final String typeName;
	private final Set<ClassTypeInfo> virtualParents;
	private final Map<ClassTypeInfo, Integer> baseOffsets;

	private RttiModelWrapper(Rtti1Model model) throws InvalidDataTypeException {
		Program program = model.getProgram();
		this.baseModel = model;
		this.type = model.getRtti0Model();
		this.hierarchyDescriptor =
			new Rtti3Model(program, model.getRtti3Address(), DEFAULT_OPTIONS);
		this.baseArray = hierarchyDescriptor.getRtti2Model();
		this.completeObjectLocator = null;
		this.parents = doGetParentModels();
		this.vtable = doGetVtable();
		this.builder = new VsCppClassBuilder(this);
		this.typeName = type.getTypeName();
		this.virtualParents = doGetVirtualParents();
		this.baseOffsets = doGetBaseOffsets();
	}

	private RttiModelWrapper(Rtti4Model model) throws InvalidDataTypeException {
		model.validate();
		this.completeObjectLocator = model;
		this.type = model.getRtti0Model();
		type.validate();
		this.hierarchyDescriptor = model.getRtti3Model();
		hierarchyDescriptor.validate();
		this.baseArray = hierarchyDescriptor.getRtti2Model();
		baseArray.validate();
		this.baseModel = baseArray.getRtti1Model(0);
		baseModel.validate();
		this.parents = doGetParentModels();
		this.vtable = doGetVtable();
		this.builder = new VsCppClassBuilder(this);
		this.typeName = type.getTypeName();
		this.virtualParents = doGetVirtualParents();
		this.baseOffsets = doGetBaseOffsets();
	}

	private RttiModelWrapper(Rtti3Model model) throws InvalidDataTypeException {
		model.validate();
		this.hierarchyDescriptor = model;
		this.type = model.getRtti0Model();
		type.validate();
		this.baseArray = model.getRtti2Model();
		baseArray.validate();
		this.baseModel = baseArray.getRtti1Model(0);
		baseModel.validate();
		this.completeObjectLocator = null;
		this.parents = doGetParentModels();
		this.vtable = doGetVtable();
		this.builder = new VsCppClassBuilder(this);
		this.typeName = type.getTypeName();
		this.virtualParents = doGetVirtualParents();
		this.baseOffsets = doGetBaseOffsets();
	}

	private static AssertException getPreValidatedError(InvalidDataTypeException e, Address a) {
		String msg = String.format("Previously validated data at %s is no longer valid", a);
		return new AssertException(msg, e);
	}

	private static ClassTypeInfo wrapNoExcept(Rtti1Model model) {
		// models must have already been checked
		try {
			Program program = model.getProgram();
			ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
			ClassTypeInfo parent = manager.getType(model.getRtti0Address());
			if (parent != null) {
				return parent;
			}
			return manager.resolve(new RttiModelWrapper(model));
		} catch (InvalidDataTypeException e) {
			throw getPreValidatedError(e, model.getAddress());
		}
	}

	public static RttiModelWrapper getWrapper(TypeDescriptorModel typeModel, TaskMonitor monitor)
			throws CancelledException {
		RttiModelSearcher searcher = new RttiModelSearcher(typeModel);
		searcher.search(monitor);
		AnyRttiModel any = searcher.getSearchResult();
		try {
			if (any.isRtti4Model()) {
				return new RttiModelWrapper(any.getRtti4Model());
			}
			if (any.isRtti3Model()) {
				return new RttiModelWrapper(any.getRtti3Model());
			}
		} catch (InvalidDataTypeException e) {
			// impossible
			throw new AssertException(e);
		}
		// Not enough information to wrap. This is valid
		return null;
	}

	public Rtti1Model getBaseModel() {
		return baseModel;
	}

	@Override
	public TypeDescriptorModel getTypeDescriptor() {
		return type;
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof RttiModelWrapper) {
			return type.equals(((RttiModelWrapper) o).type);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return getAddress().hashCode();
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
		return parents.length > 0;
	}

	private List<Address> getVftableAddresses() {
		final SymbolTable table = type.getProgram().getSymbolTable();
		SymbolIterator symbols = table.getChildren(getNamespace().getSymbol());
		int pointerSize = type.getProgram().getDefaultPointerSize();
		return StreamSupport.stream(symbols.spliterator(), false)
			.filter(s -> s.getName().equals(VFTABLE_SYMBOL_NAME))
			.map(Symbol::getAddress)
			.map(a -> a.add(pointerSize))
			.sorted()
			.collect(Collectors.toList());
	}

	@Override
	public ClassTypeInfo[] getParentModels() {
		return parents;
	}

	private static List<Rtti1Model> getRtti1Models(Program program, Address addr, int count) {
		List<Rtti1Model> result = new ArrayList<>(count-1);
		int size = 4;
		Address currentAddr = addr.add(size);
		for (int i = 1; i < count; i++) {
			// start at 1 since the first base is this
			Address address = getReferencedAddress(program, currentAddr);
			Rtti1Model model = new Rtti1Model(program, address, DEFAULT_OPTIONS);
			try {
				model.validate();
				result.add(model);
			} catch (InvalidDataTypeException e) {
				throw getPreValidatedError(e, address);
			}
			currentAddr = currentAddr.add(size);
		}
		return result;
	}

	private ClassTypeInfo[] doGetParentModels() {
		Program program = type.getProgram();
		Address addr = hierarchyDescriptor.getAddress();
		int baseCount = Rtti3Model.getRtti1Count(program, addr);
		return getRtti1Models(program, baseArray.getAddress(), baseCount)
			.stream()
			.filter(Predicate.not(this::shouldIgnore))
			.map(RttiModelWrapper::wrapNoExcept)
			.toArray(ClassTypeInfo[]::new);
	}

	static boolean isVirtual(Rtti1Model model) throws InvalidDataTypeException {
		return (model.getAttributes() >> 4 & 1) == 1;
	}

	private Vtable doGetVtable() {
		final List<Address> addresses = getVftableAddresses();
		if (!addresses.isEmpty()) {
			return new VsVtableModel(type.getProgram(), getVftableAddresses(), this);
		}
		return Vtable.NO_VTABLE;
	}

	@Override
	public Vtable getVtable() {
		return vtable;
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		return getVtable();
	}

	private int getVirtualOffset(Rtti1Model model) {
		if (Vtable.isValid(vtable)) {
			try {
				return ((VsVtableModel) vtable).getVirtualOffset(model);
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
	public Set<ClassTypeInfo> getVirtualParents() {
		return virtualParents;
	}

	private Set<ClassTypeInfo> doGetVirtualParents() throws InvalidDataTypeException {
		Set<ClassTypeInfo> result = new LinkedHashSet<>();
		int baseCount = hierarchyDescriptor.getRtti1Count();
		for (int i = 1; i < baseCount; i++) {
			Rtti1Model model = baseArray.getRtti1Model(i);
			ClassTypeInfo parent = wrapNoExcept(model);
			result.addAll(parent.getVirtualParents());
			if (isVirtual(model)) {
				result.add(wrapNoExcept(model));
			}
		}
		return result;
	}

	public Map<ClassTypeInfo, Integer> getBaseOffsets() {
		return baseOffsets;
	}

	private Map<ClassTypeInfo, Integer> doGetBaseOffsets() throws InvalidDataTypeException {
		Map<ClassTypeInfo, Integer> map = new HashMap<>();
		for (int i = 1; i < baseArray.getCount(); i++) {
			Rtti1Model base = baseArray.getRtti1Model(i);
			if (!shouldIgnore(base)) {
				map.put(wrapNoExcept(base), getOffset(base));
			}
		}
		return map;
	}

	@Override
	public Structure getClassDataType() {
		return builder.getDataType();
	}

	@Override
	public Rtti3Model getHierarchyDescriptor() {
		return hierarchyDescriptor;
	}

	@Override
	public Rtti4Model getCompleteObjectLocator() {
		return completeObjectLocator;
	}
}
