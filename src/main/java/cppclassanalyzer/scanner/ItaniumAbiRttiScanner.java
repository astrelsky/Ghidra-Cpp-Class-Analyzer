package cppclassanalyzer.scanner;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.*;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.util.XReferenceUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.manager.ItaniumAbiClassTypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

public class ItaniumAbiRttiScanner implements RttiScanner {

	// The only one excluded is BaseClassTypeInfoModel
	protected static final List<String> CLASS_TYPESTRINGS = List.of(
		ClassTypeInfoModel.ID_STRING,
		SiClassTypeInfoModel.ID_STRING,
		VmiClassTypeInfoModel.ID_STRING
	);

	protected static final List<String> FUNDAMENTAL_TYPESTRINGS = List.of(
		FundamentalTypeInfoModel.ID_STRING,
		PBaseTypeInfoModel.ID_STRING,
		PointerToMemberTypeInfoModel.ID_STRING,
		PointerTypeInfoModel.ID_STRING,
		ArrayTypeInfoModel.ID_STRING,
		EnumTypeInfoModel.ID_STRING,
		FunctionTypeInfoModel.ID_STRING,
		IosFailTypeInfoModel.ID_STRING
	);

	protected final ItaniumAbiClassTypeInfoManager manager;
	protected TaskMonitor monitor;
	protected MessageLog log;
	private Set<Relocation> relocations;
	private boolean relocatable;
	private boolean reportedMissingRtti = false;

	public ItaniumAbiRttiScanner(Program program) {
		this.manager =
				(ItaniumAbiClassTypeInfoManager) CppClassAnalyzerUtils.getManager(program);
		this.relocations = new HashSet<>();
	}

	protected String getDynamicSymbol(String symbol) {
		return symbol;
	}

	protected String getDynamicSymbol(Relocation relocation) {
		return relocation.getSymbolName();
	}

	protected final ItaniumAbiClassTypeInfoManager getManager() {
		return manager;
	}

	protected final TaskMonitor getDummyMonitor() {
		return new CancelOnlyWrappingTaskMonitor(monitor);
	}

	protected final MessageLog getLog() {
		return log;
	}

	protected final TaskMonitor getMonitor() {
		return monitor;
	}

	protected final Program getProgram() {
		return manager.getProgram();
	}

	public boolean isTypeInfo(Address address) {
		return TypeInfoFactory.isTypeInfo(getProgram(), address);
	}

	public TypeInfo getTypeInfo(Address address) {
		return TypeInfoFactory.getTypeInfo(getProgram(), address);
	}

	protected final Set<Relocation> getRelocations() {
		return relocations;
	}

	protected final void setLog(MessageLog log) {
		this.log = log;
	}

	protected final void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	@Override
	public boolean scan(MessageLog log, TaskMonitor monitor) throws CancelledException {
		this.log = log;
		this.monitor = monitor;
		relocations.addAll(getRelocations(CLASS_TYPESTRINGS));
		if (!relocations.isEmpty()) {
			relocatable = true;
			createOffcutVtableRefs(relocations);
		}
		if (!relocatable) {
			TypeInfo ti = TypeInfoUtils.findTypeInfo(
				getProgram(), getProgram().getMemory(),
				TypeInfoModel.ID_STRING, getDummyMonitor());
			if (ti == null) {
				return false;
			}
		}
		return doScan(log, monitor);
	}

	protected boolean doScan(MessageLog log, TaskMonitor monitor) throws CancelledException {
		try {
			/* Create the vmi replacement base to prevent a
			   placeholder struct from being generated  */
			addDataTypes();
			applyTypeInfoTypes(TypeInfoModel.ID_STRING);
			for (String typeString : CLASS_TYPESTRINGS) {
				applyTypeInfoTypes(typeString);
			}
			relocations.clear();
			return true;
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
	}

	@Override
	public Set<Address> scanFundamentals(MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		this.monitor = monitor;
		relocations.addAll(getRelocations(CLASS_TYPESTRINGS));
		if (!relocations.isEmpty()) {
			relocatable = true;
			createOffcutVtableRefs(relocations);
		}
		Set<Address> addresses = new TreeSet<>();
		for (String typeString : FUNDAMENTAL_TYPESTRINGS) {
			monitor.checkCancelled();
			try {
				addresses.addAll(getReferences(typeString));
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				log.appendException(e);
			}
		}
		relocations.clear();
		return addresses;
	}

	private void addDataTypes() {
		DataTypeManager dtm = getProgram().getDataTypeManager();
		dtm.resolve(VmiClassTypeInfoModel.getDataType(dtm), REPLACE_HANDLER);
	}

	private void addReferences(AddressSet addresses) throws CancelledException {
		if (addresses.isEmpty()) {
			return;
		}
		Program program = getProgram();
		TaskMonitor dummy = getDummyMonitor();
		Memory mem = program.getMemory();
		ReferenceManager refMan = program.getReferenceManager();
		List<ReferenceAddressPair> refList = new LinkedList<>();
		ProgramMemoryUtil.loadDirectReferenceList(
			program, program.getDefaultPointerSize(), addresses.getMinAddress(),
			addresses, refList, dummy);
		monitor.setProgress(monitor.getMaximum());
		for (ReferenceAddressPair ref : refList) {
			monitor.checkCancelled();
			if (CppClassAnalyzerUtils.isDataBlock(mem.getBlock(ref.getSource()))) {
				refMan.addMemoryReference(
					ref.getSource(), ref.getDestination(),
					RefType.DATA, SourceType.ANALYSIS, 0);
			}
		}
	}

	private void applyTypeInfoTypes(String typeString) throws Exception {
		Program program = getProgram();
		boolean isClass = CLASS_TYPESTRINGS.contains(typeString);
		Set<Address> types = getReferences(typeString);
		if (types.isEmpty()) {
			return;
		}
		Namespace typeClass = TypeInfoUtils.getNamespaceFromTypeName(program, typeString);
		monitor.initialize(types.size());
		monitor.setMessage(
				"Scanning for "+typeClass.getName()+" structures");
		for (Address reference : types) {
			monitor.checkCancelled();
			try {
				TypeInfo type = getTypeInfo(reference);
				if (type != null) {
					if (isClass) {
						ClassTypeInfo classType = ((ClassTypeInfo) type);
						manager.resolve(classType);
						classType.getGhidraClass();
					}
				}
			} catch (UnresolvedClassTypeInfoException e) {
				if (!reportedMissingRtti) {
					log.appendMsg(
						"Missing dynamic RTTI detected. Not all RTTI created.\n"
						+ "See README for more information on how to fix this.");
					reportedMissingRtti = true;
				}
			} catch (Exception e) {
				if (e instanceof IndexOutOfBoundsException) {
					e.printStackTrace();
				}
				//log.appendException(e);
			}
			monitor.incrementProgress(1);
		}
	}

	private void createOffcutVtableRefs(Set<Relocation> relocs) throws CancelledException {
		Listing listing = getProgram().getListing();
		AddressSet addresses = new AddressSet();
		relocs.stream()
			.map(Relocation::getAddress)
			.map(listing::getDataAt)
			.filter(Objects::nonNull)
			.forEach(d -> addresses.add(d.getMinAddress(), d.getMaxAddress()));
		addReferences(addresses);
	}

	private Set<Address> getClangDynamicReferences(Address address) throws CancelledException {
		Data data = getProgram().getListing().getDataContaining(address);
		if (data == null) {
			log.appendMsg("Null data at clang relocation");
			return null;
		}
		return XReferenceUtils.getOffcutXReferences(data, -1)
			.stream()
			.filter(r -> r.getReferenceType().isData())
			.map(Reference::getFromAddress)
			.collect(Collectors.toSet());
	}

	private Set<Address> getDynamicReferences(String typeString) throws CancelledException {
		String target = getDynamicSymbol(VtableModel.MANGLED_PREFIX+typeString);
		Set<Address> result = relocations.stream()
			.filter(r -> target.equals(getDynamicSymbol(r)))
			.map(Relocation::getAddress)
			.collect(Collectors.toSet());
		if (result.size() == 1) {
			Set<Address> clangResults =
				getClangDynamicReferences(result.toArray(Address[]::new)[0]);
			if (!clangResults.isEmpty()) {
				return clangResults;
			}
		}
		return result;
	}

	protected Set<Address> getReferences(String typeString) throws Exception {
		if (relocatable) {
			return getDynamicReferences(typeString);
		}
		return getStaticReferences(typeString);
	}

	private Set<Relocation> getRelocations(List<String> names) {
		Set<String> symbols = names.stream()
			.map(n -> VtableModel.MANGLED_PREFIX+n)
			.map(this::getDynamicSymbol)
			.collect(Collectors.toSet());
		Iterator<Relocation> relocations = getProgram().getRelocationTable()
			.getRelocations();
		List<Relocation> relocs = CollectionUtils.asStream(relocations)
			.filter(r -> r.getSymbolName() != null)
			.collect(Collectors.toList());
		return relocs.stream()
			.filter(r -> symbols.contains(getDynamicSymbol(r)))
			.collect(Collectors.toSet());
	}

	private Set<Address> getStaticReferences(String typeString) throws Exception {
		try {
			Program program = getProgram();
			TaskMonitor dummy = getDummyMonitor();
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
}
