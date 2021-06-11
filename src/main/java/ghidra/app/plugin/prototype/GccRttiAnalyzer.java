package ghidra.app.plugin.prototype;

import java.util.*;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import ghidra.framework.options.Options;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.SettingsDefinition;

import cppclassanalyzer.data.manager.ItaniumAbiClassTypeInfoManager;
import cppclassanalyzer.scanner.RttiScanner;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.program.model.mem.Memory;
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

import static ghidra.app.cmd.data.rtti.GnuVtable.PURE_VIRTUAL_FUNCTION_NAME;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class GccRttiAnalyzer extends AbstractAnalyzer {

	public static final String ANALYZER_NAME = "GCC RTTI Analyzer";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the RTTI metadata structures and their associated vtables.";

	private static final String OPTION_FUNDAMENTAL_NAME = "Find Fundamental Types";
	private static final boolean OPTION_DEFAULT_FUNDAMENTAL = false;
	private static final String OPTION_FUNDAMENTAL_DESCRIPTION =
		"Turn on to scan for __fundamental_type_info and its derivatives.";

	private static final String OPTION_BOOKMARKS_NAME = "Create Bookmarks";
	private static final boolean OPTION_DEFAULT_BOOKMARKS = true;
	private static final String OPTION_BOOKMARKS_DESCRIPTION =
		"Turn on to create bookmarks at located RTTI metadata";

	private boolean fundamentalOption;
	private boolean createBookmarks;

	// The only one excluded is BaseClassTypeInfoModel
	private static final List<String> CLASS_TYPESTRINGS = List.of(
		ClassTypeInfoModel.ID_STRING,
		SiClassTypeInfoModel.ID_STRING,
		VmiClassTypeInfoModel.ID_STRING
	);

	private Program program;
	private BookmarkManager bMan;
	private TaskMonitor monitor;
	private MessageLog log;
	private CancelOnlyWrappingTaskMonitor dummy;
	private Set<Relocation> relocations;
	private ItaniumAbiClassTypeInfoManager manager;
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
		if (CppClassAnalyzerUtils.getManager(program) != null) {
			return GnuUtils.isGnuCompiler(program);
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
			this.program = program;
			this.bMan = program.getBookmarkManager();
			this.set = new AddressSet();
			this.monitor = monitor;
			this.dummy = new CancelOnlyWrappingTaskMonitor(monitor);
			this.log = log;
			this.manager =
				(ItaniumAbiClassTypeInfoManager) CppClassAnalyzerUtils.getManager(program);
			if (this.manager == null) {
				return false;
			}
			try {
				RttiScanner scanner = RttiScanner.getScanner(program);
				if (fundamentalOption) {
					for (Address addr : scanner.scanFundamentals(log, monitor)) {
						monitor.checkCanceled();
						TypeInfo type = manager.getTypeInfo(addr);
						applyTypeInfo(type);
					}
				}
				scanner.scan(log, monitor);
				monitor.initialize(manager.getTypeCount());
				monitor.setMessage("Creating ClassTypeInfo's");
				for (ClassTypeInfo type : manager.getTypes()) {
					monitor.checkCanceled();
					applyTypeInfo(type);
					this.set.add(type.getAddress());
					monitor.incrementProgress(1);
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

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		relocations.clear();
		relocations = null;
		// this is the default result
		return false;
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
		pureVirtual.setName(PURE_VIRTUAL_FUNCTION_NAME, SourceType.IMPORTED);
		pureVirtual.setNoReturn(true);
		pureVirtual.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
		try {
			String cc = GenericCallingConvention.stdcall.getDeclarationName();
			pureVirtual.setCallingConvention(cc);
		} catch (Exception e) {
			// compiler spec doesn't have __stdcall
		}
	}

	private void createVtable(GnuVtable vtable) throws Exception {
		if (vtable == Vtable.NO_VTABLE) {
			return;
		}
		CreateVtableBackgroundCmd vtableCmd = new CreateVtableBackgroundCmd(vtable);
		vtableCmd.applyTo(program, dummy);
		markDataAsConstant(vtable.getAddress());
		if (createBookmarks) {
			bMan.setBookmark(
				vtable.getAddress(), BookmarkType.ANALYSIS,
				BookmarkType.ANALYSIS, "vtable located");
		}
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
		markDataAsConstant(vtt.getAddress());
		if (createBookmarks) {
			bMan.setBookmark(
				vtt.getAddress(), BookmarkType.ANALYSIS,
				BookmarkType.ANALYSIS, "vtt located");
			for (GnuVtable vtable : vtt.getConstructionVtableModels()) {
				bMan.setBookmark(
					vtable.getAddress(), BookmarkType.ANALYSIS,
					BookmarkType.ANALYSIS, "construction vtable located");
			}
		}
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

	private void applyTypeInfo(TypeInfo type) {
		CreateTypeInfoBackgroundCmd cmd = new CreateTypeInfoBackgroundCmd(type);
		cmd.applyTo(program, dummy);
		markDataAsConstant(type.getAddress());
		if (createBookmarks) {
			Address typenameAddress = getAbsoluteAddress(
				program, type.getAddress().add(program.getDefaultPointerSize()));
			bMan.setBookmark(
				type.getAddress(), BookmarkType.ANALYSIS,
				BookmarkType.ANALYSIS, "typeinfo located");
			bMan.setBookmark(
					typenameAddress, BookmarkType.ANALYSIS,
					BookmarkType.ANALYSIS, "typeinfo-name located");
		}
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		options.registerOption(OPTION_FUNDAMENTAL_NAME, OPTION_DEFAULT_FUNDAMENTAL, null,
			OPTION_FUNDAMENTAL_DESCRIPTION);
		options.registerOption(OPTION_BOOKMARKS_NAME, OPTION_DEFAULT_BOOKMARKS, null,
			OPTION_BOOKMARKS_DESCRIPTION);
		fundamentalOption =
			options.getBoolean(OPTION_FUNDAMENTAL_NAME, OPTION_DEFAULT_FUNDAMENTAL);
		createBookmarks =
			options.getBoolean(OPTION_BOOKMARKS_NAME, OPTION_DEFAULT_BOOKMARKS);
	}
}
