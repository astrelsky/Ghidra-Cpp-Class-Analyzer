package ghidra.app.plugin.prototype;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.options.Options;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.SettingsDefinition;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.services.*;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSetView;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.*;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.cmd.data.rtti.GnuVtable.PURE_VIRTUAL_FUNCTION_NAME;

public class GccRttiAnalyzer extends AbstractAnalyzer {

	public static final String ANALYZER_NAME = "GCC RTTI Analyzer";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the RTTI metadata structures and their associated vtables.";

	private static final String OPTION_FUNDAMENTAL_NAME = "Find Fundamental Types";
	private static final boolean OPTION_DEFAULT_FUNDAMENTAL = false;
	private static final String OPTION_FUNDAMENTAL_DESCRIPTION =
		"Turn on to scan for __fundamental_type_info and its derivatives.";

	private boolean fundamentalOption;

	private Program program;
	private TaskMonitor monitor;
	private MessageLog log;
	private CancelOnlyWrappingTaskMonitor dummy;

	// The only one excluded is BaseClassTypeInfoModel
	private static final List<String> CLASS_TYPESTRINGS = List.of(
		ClassTypeInfoModel.ID_STRING,
		SiClassTypeInfoModel.ID_STRING,
		VmiClassTypeInfoModel.ID_STRING
	);

	private static final List<String> FUNDAMENTAL_TYPESTRINGS = List.of(
		FundamentalTypeInfoModel.ID_STRING,
		PBaseTypeInfoModel.ID_STRING,
		PointerToMemberTypeInfoModel.ID_STRING,
		PointerTypeInfoModel.ID_STRING,
		ArrayTypeInfoModel.ID_STRING,
		EnumTypeInfoModel.ID_STRING,
		FunctionTypeInfoModel.ID_STRING,
		IosFailTypeInfoModel.ID_STRING
	);

	private ProgramClassTypeInfoManager manager;
	private boolean relocatable;
	private AddressSet set;

	// if a typename contains this, vftable components index >= 2 point to __cxa_pure_virtual
	private static final String PURE_VIRTUAL_CONTAINING_STRING = "abstract_base";

	/**
	 * Constructs an RttiAnalyzer.
	 */
	public GccRttiAnalyzer() {
		super(ANALYZER_NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
		setDefaultEnablement(true);
		setPrototype();
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (ClassTypeInfoManagerService.isEnabled(program)) {
			return GnuUtils.isGnuCompiler(program);
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
			this.program = program;
			this.set = new AddressSet();
			this.monitor = monitor;
			this.log = log;
			this.manager = CppClassAnalyzerUtils.getManager(program);
			if (this.manager == null) {
				return false;
			}

			this.relocatable = program.getRelocationTable().isRelocatable();
			Set<Relocation> relocations = getRelocations(CLASS_TYPESTRINGS);
			if (relocations.size() == CLASS_TYPESTRINGS.size()) {
				relocatable = true;
				if (fundamentalOption) {
					relocations.addAll(getRelocations(FUNDAMENTAL_TYPESTRINGS));
				}
				createOffcutVtableRefs(relocations);
			}

			dummy = new CancelOnlyWrappingTaskMonitor(monitor);
			for (String typeString : CLASS_TYPESTRINGS) {
				if (!getDynamicReferences(typeString).isEmpty()) {
					relocatable = true;
					break;
				}
			}
			if (!relocatable) {
				if (TypeInfoUtils.findTypeInfo(
					program, set, TypeInfoModel.ID_STRING, dummy) == null) {
						return false;
					}
			}

			try {
				/* Create the vmi replacement base to prevent a
				   placeholder struct from being generated  */
				addDataTypes();
				if (fundamentalOption) {
					for (String typeString : FUNDAMENTAL_TYPESTRINGS) {
						applyTypeInfoTypes(typeString);
					}
				}
				applyTypeInfoTypes(TypeInfoModel.ID_STRING);
				for (String typeString : CLASS_TYPESTRINGS) {
					applyTypeInfoTypes(typeString);
				}
				createVtables();
				createVtts();
				return true;
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				e.printStackTrace();
				log.appendMsg("Ghidra-Cpp-Class-Analyzer", e.getMessage());
				return false;
			}
	}

	private void createOffcutVtableRefs(Set<Relocation> relocs) throws CancelledException {
		Listing listing = program.getListing();
		AddressSet addresses = new AddressSet();
		relocs.stream()
			.map(Relocation::getAddress)
			.map(listing::getDataAt)
			.filter(Objects::nonNull)
			.forEach(d -> addresses.add(d.getMinAddress(), d.getMaxAddress()));
		addReferences(addresses);
	}

	private void addReferences(AddressSet addresses) throws CancelledException {
		if (addresses.isEmpty()) {
			return;
		}
		Memory mem = program.getMemory();
		ReferenceManager refMan = program.getReferenceManager();
		List<ReferenceAddressPair> refList = new LinkedList<>();
		ProgramMemoryUtil.loadDirectReferenceList(
			program, program.getDefaultPointerSize(), addresses.getMinAddress(),
			addresses, refList, dummy);
		monitor.setProgress(monitor.getMaximum());
		for (ReferenceAddressPair ref : refList) {
			monitor.checkCanceled();
			if (CppClassAnalyzerUtils.isDataBlock(mem.getBlock(ref.getSource()))) {
				refMan.addMemoryReference(
					ref.getSource(), ref.getDestination(),
					RefType.DATA, SourceType.ANALYSIS, 0);
			}
		}
	}

	private void addDataTypes() {
		DataTypeManager dtm = program.getDataTypeManager();
		dtm.resolve(VmiClassTypeInfoModel.getDataType(dtm), REPLACE_HANDLER);
	}

	private boolean checkTableAddresses(Function[][] functionTables) {
		if (functionTables.length == 0 || functionTables[0].length < 3) {
			return false;
		}
		if (functionTables[0].length >= 3) {
			// sanity check. This is only possible for __cxa_pure_virtual
			if (functionTables[0][2] == null || functionTables[0][3] == null) {
				return false;
			}
			return functionTables[0][2].equals(functionTables[0][3]);
		}
		return false;
	}

	private static boolean isPureVirtualType(ClassTypeInfo type) {
		return type.getTypeName().contains(PURE_VIRTUAL_CONTAINING_STRING);
	}

	private Function getPureVirtualFunction() throws CancelledException {
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(PURE_VIRTUAL_FUNCTION_NAME)) {
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				return (Function) symbol.getObject();
			}
		}
		for (ClassTypeInfo type : manager.getTypes()) {
			monitor.checkCanceled();
			if (isPureVirtualType(type)) {
				try {
					Vtable vtable = type.findVtable(dummy);
					if (Vtable.isValid(vtable)) {
						Function[][] ftables = vtable.getFunctionTables();
						if (checkTableAddresses(ftables)) {
							return ftables[0][2];
						}
					}
				} catch (Exception e) {
				}
			}
		}
		return null;
	}

	private void findAndCreatePureVirtualFunction() throws Exception {
		monitor.setMessage("Locating "+PURE_VIRTUAL_FUNCTION_NAME);
		Function pureVirtual = getPureVirtualFunction();
		if (pureVirtual == null) {
			return;
		}
		String cc = GenericCallingConvention.stdcall.getDeclarationName();
		pureVirtual.setName(PURE_VIRTUAL_FUNCTION_NAME, SourceType.IMPORTED);
		pureVirtual.setNoReturn(true);
		pureVirtual.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
		pureVirtual.setCallingConvention(cc);
	}

	private void createVtable(GnuVtable vtable) throws Exception {
		if (vtable == Vtable.NO_VTABLE) {
			return;
		}
		CreateVtableBackgroundCmd vtableCmd = new CreateVtableBackgroundCmd(vtable);
		vtableCmd.applyTo(program, dummy);
		markDataAsConstant(vtable.getAddress());
		if (!vtable.getTypeInfo().isAbstract()) {
			for (Address tableAddress : vtable.getTableAddresses()) {
				markDataAsConstant(tableAddress);
			}
		}
	}

	public final void markDataAsConstant(Address address) {
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			return;
		}
		SettingsDefinition[] settings = data.getDataType().getSettingsDefinitions();
		for (SettingsDefinition setting : settings) {
			if (setting instanceof MutabilitySettingsDefinition) {
				MutabilitySettingsDefinition mutabilitySetting =
					(MutabilitySettingsDefinition) setting;
				mutabilitySetting.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
			}
		}
	}

	private void createVtts() throws Exception {
		for (Vtable vtable : manager.getVtables()) {
			for (Address addr : vtable.getTableAddresses()) {
				set.add(addr);
			}
		}
		monitor.setMessage("Creating Vtable References");
		addReferences(set);
		set.clear();
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Locating VTTs");
		for (Vtable vtable : manager.getVtables()) {
			monitor.checkCanceled();
			try {
				locateVTT((GnuVtable) vtable);
			} catch (Exception e) {
				log.appendException(e);
			}
			monitor.incrementProgress(1);
		}
	}

	private void locateVTT(GnuVtable vtable) throws Exception {
		ClassTypeInfo type = vtable.getTypeInfo();
		if (!CLASS_TYPESTRINGS.contains(type.getTypeName())) {
			VttModel vtt = VtableUtils.getVttModel(program, vtable);
			if (vtt.isValid()) {
				createVtt(type, vtt);
			}
		}
	}

	private void createVtt(ClassTypeInfo type, VttModel vtt) {
		CreateVttBackgroundCmd cmd =
			new CreateVttBackgroundCmd(vtt, type);
		cmd.applyTo(program, dummy);
	}

	private void createVtables() throws Exception {
		findAndCreatePureVirtualFunction();
		monitor.setMessage("Creating ClassTypeInfo References");
		addReferences(set);
		set.clear();
		manager.findVtables(monitor, log);
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Creating vtables");
		for (Vtable vtable : manager.getVtables()) {
			monitor.checkCanceled();
			try {
				createVtable((GnuVtable) vtable);
			} catch (Exception e) {
				log.appendMsg("Unable to create vtable for "+vtable.getTypeInfo().getFullName());
			}
			monitor.incrementProgress(1);
		}
	}

	private Set<Address> getStaticReferences(String typeString) throws Exception {
		try {
			ClassTypeInfo typeinfo = (ClassTypeInfo) TypeInfoUtils.findTypeInfo(
				program, typeString, dummy);
			monitor.setMessage("Locating vtable for "+typeinfo.getName());
			Vtable vtable = typeinfo.findVtable(dummy);
			if (!Vtable.isValid(vtable)) {
				throw new Exception("Vtable for "+typeinfo.getFullName()+" not found");
			}
			return GnuUtils.getDirectDataReferences(
				program, vtable.getTableAddresses()[0], dummy);
		} catch (NullPointerException e) {
			return Collections.emptySet();
		}
	}

	private AddressSetView getDataAddressSet() {
		AddressSet set = new AddressSet();
		for (MemoryBlock block : CppClassAnalyzerUtils.getAllDataBlocks(program)) {
			set.add(block.getStart(), block.getEnd());
		}
		return set;
	}

	private Set<Address> getClangDynamicReferences(Address address) throws CancelledException {
		Data data = program.getListing().getDataContaining(address);
		if (data == null) {
			log.appendMsg("Null data at clang relocation");
			return null;
		}
		return Arrays.stream(XReferenceUtil.getOffcutXReferences(data, -1))
			.filter(r -> r.getReferenceType().isData())
			.map(Reference::getFromAddress)
			.collect(Collectors.toSet());
	}

	private Set<Address> getDynamicReferences(String typeString) throws CancelledException {
		String target = VtableModel.MANGLED_PREFIX+typeString;
		Iterator<Relocation> relocations = program.getRelocationTable()
			.getRelocations(getDataAddressSet());
		Set<Address> result = CollectionUtils.asStream(relocations)
			.filter(r -> r.getSymbolName() != null && r.getSymbolName().equals(target))
			.map(Relocation::getAddress)
			.collect(Collectors.toSet());
		if (result.size() == 1) {
			return getClangDynamicReferences(result.toArray(Address[]::new)[0]);
		}
		return result;
	}

	private Set<Relocation> getRelocations(List<String> names) {
		Set<String> symbols = names.stream()
			.map(n -> VtableModel.MANGLED_PREFIX+n)
			.collect(Collectors.toSet());
		Iterator<Relocation> relocations = program.getRelocationTable()
			.getRelocations(getDataAddressSet());
		return CollectionUtils.asStream(relocations)
			.filter(r -> r.getSymbolName() != null && symbols.contains(r.getSymbolName()))
			.collect(Collectors.toSet());
	}

	private Set<Address> getReferences(String typeString) throws Exception {
		if (relocatable) {
			return getDynamicReferences(typeString);
		}
		return getStaticReferences(typeString);
	}

	private void applyTypeInfoTypes(String typeString) throws Exception {
		Listing listing = program.getListing();
		boolean isClass = CLASS_TYPESTRINGS.contains(typeString);
		Set<Address> types = getReferences(typeString);
		if (types.isEmpty()) {
			return;
		}
		Namespace typeClass = TypeInfoUtils.getNamespaceFromTypeName(program, typeString);
		monitor.initialize(types.size());
		monitor.setMessage(
				"Creating "+typeClass.getName()+" structures");
		for (Address reference : types) {
			monitor.checkCanceled();
			try {
				TypeInfo type = manager.getTypeInfo(reference);
				if (type != null) {
					if (isClass) {
						ClassTypeInfo classType = ((ClassTypeInfo) type);
						manager.resolve(classType);
						classType.getGhidraClass();
					}
					Data data = listing.getDataAt(reference);
					if (data == null || !data.getDataType().isEquivalent(type.getDataType())) {
						set.add(reference);
					}
					CreateTypeInfoBackgroundCmd cmd = new CreateTypeInfoBackgroundCmd(type);
					cmd.applyTo(program, dummy);
					markDataAsConstant(type.getAddress());
				}
			} catch (UnresolvedClassTypeInfoException e) {
				log.appendMsg(e.getMessage());
			} catch (Exception e) {
				if (e instanceof IndexOutOfBoundsException) {
					e.printStackTrace();
				}
				//log.appendException(e);
			}
			monitor.incrementProgress(1);
		}
	}


	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		options.registerOption(OPTION_FUNDAMENTAL_NAME, OPTION_DEFAULT_FUNDAMENTAL, null,
			OPTION_FUNDAMENTAL_DESCRIPTION);

		fundamentalOption =
			options.getBoolean(OPTION_FUNDAMENTAL_NAME, OPTION_DEFAULT_FUNDAMENTAL);
	}
}
