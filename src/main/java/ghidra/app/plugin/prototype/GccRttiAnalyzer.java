package ghidra.app.plugin.prototype;

import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.options.Options;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.address.AddressSetView;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.*;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.PURE_VIRTUAL_FUNCTION_NAME;

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
	private CancelOnlyWrappingTaskMonitor dummy;

	// The only one excluded is BaseClassTypeInfoModel
	private static final List<String> CLASS_TYPESTRINGS = List.of(
		ClassTypeInfoModel.ID_STRING,
		SiClassTypeInfoModel.ID_STRING,
		VmiClassTypeInfoModel.ID_STRING
	);

	private static final String[] FUNDAMENTAL_TYPESTRINGS = new String[] {
		FundamentalTypeInfoModel.ID_STRING,
		PBaseTypeInfoModel.ID_STRING,
		PointerToMemberTypeInfoModel.ID_STRING,
		PointerTypeInfoModel.ID_STRING,
		ArrayTypeInfoModel.ID_STRING,
		EnumTypeInfoModel.ID_STRING,
		FunctionTypeInfoModel.ID_STRING,
		IosFailTypeInfoModel.ID_STRING
	};

	private ProgramClassTypeInfoManager manager;
	private boolean relocatable;

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
			this.monitor = monitor;

			this.manager = CppClassAnalyzerUtils.getManager(program);
			if (this.manager == null) {
				return false;
			}

			this.relocatable = program.getRelocationTable().isRelocatable();

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
						log.appendMsg(this.getName(), "RTTI not detected");
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
				return true;
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				e.printStackTrace();
				log.error("Ghidra-Cpp-Class-Analyzer", e.getMessage());
				return false;
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
			return functionTables[0][2].equals(functionTables[0][3]);
		}
		return false;
	}

	private static boolean isPureVirtualType(ClassTypeInfo type) {
		return type.getTypeName().contains(PURE_VIRTUAL_CONTAINING_STRING);
	}

	private Stream<ClassTypeInfoDB> getStream() {
		Iterable<ClassTypeInfoDB> iter = manager.getTypes();
		return StreamSupport.stream(iter.spliterator(), false);
	}

	private Function getPureVirtualFunction() throws CancelledException {
		try {
			final Optional<Function[][]> function =
				getStream().filter(GccRttiAnalyzer::isPureVirtualType)
					.map(ClassTypeInfo::getVtable)
					.filter(Vtable::isValid)
					.map(Vtable::getFunctionTables)
					.filter(this::checkTableAddresses)
					.findFirst();
			if (function.isPresent()) {
				// pre checked
				return function.get()[0][2];
			}
		} catch (RuntimeException e) {
			if (e.getCause() instanceof CancelledException) {
				throw (CancelledException) e.getCause();
			}
			throw e;
		}
			return null;
	}

	private void findAndCreatePureVirtualFunction() throws CancelledException,
		InvalidDataTypeException {
			monitor.setMessage("Locating "+PURE_VIRTUAL_FUNCTION_NAME);
			Function pureVirtual = getPureVirtualFunction();
			try {
				pureVirtual.setName(PURE_VIRTUAL_FUNCTION_NAME, SourceType.IMPORTED);
				pureVirtual.setNoReturn(true);
				pureVirtual.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
				pureVirtual.setCallingConvention(
					GenericCallingConvention.stdcall.getDeclarationName());
			} catch (Exception e) {
				return;
			}
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
		locateVTT(vtable);
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
		manager.findVtables(monitor);
		monitor.initialize(manager.getVtableCount());
		monitor.setMessage("Creating vtables");
		for (Vtable vtable : manager.getVtables()) {
			monitor.checkCanceled();
			createVtable((GnuVtable) vtable);
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

	private Set<Address> getClangDynamicReferences(Relocation reloc) throws CancelledException {
		Data data = program.getListing().getDataContaining(reloc.getAddress());
		if (data == null) {
			Msg.error(this, "Null data at clang relocation");
			return null;
		}
		int start = 0;
		int ptrdiffSize = GnuUtils.getPtrDiffSize(program.getDataTypeManager());
		Set<Address> result = new HashSet<>();
		while (start < data.getLength()) {
			monitor.checkCanceled();
			result.addAll(GnuUtils.getDirectDataReferences(
				program, data.getAddress().add(start), dummy));
			start += ptrdiffSize;
		}
		return result;
	}

	private Set<Address> getDynamicReferences(String typeString) throws CancelledException {
		String target = VtableModel.MANGLED_PREFIX+typeString;
		Iterator<Relocation> relocations = program.getRelocationTable()
			.getRelocations(getDataAddressSet());
		Set<Address> result = new LinkedHashSet<>();
		while (relocations.hasNext()) {
			monitor.checkCanceled();
			Relocation reloc = relocations.next();
			String name = reloc.getSymbolName();
			if (name == null) {
				continue;
			}
			if (name.equals(target)) {
				if (GnuUtils.isCopyRelocation(program, reloc.getType())) {
					return getClangDynamicReferences(reloc);
				}
				result.add(reloc.getAddress());
			}
		} return result;
	}

	private Set<Address> getReferences(String typeString) throws Exception {
		if (relocatable) {
			return getDynamicReferences(typeString);
		}
		return getStaticReferences(typeString);
	}

	private void applyTypeInfoTypes(String typeString) throws Exception {
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
			TypeInfo type = manager.getTypeInfo(reference);
			if (type != null) {
				if (isClass) {
					ClassTypeInfo classType = ((ClassTypeInfo) type);
					manager.resolve(classType);
					classType.getGhidraClass();
				}
				CreateTypeInfoBackgroundCmd cmd = new CreateTypeInfoBackgroundCmd(type);
				cmd.applyTo(program, dummy);
				markDataAsConstant(type.getAddress());
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
