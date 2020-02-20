package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WindowsCppClassAnalyzer extends AbstractCppClassAnalyzer {

	private static final String NAME = "Windows C++ Class Analyzer";
	private static final String SYMBOL_NAME = "RTTI_Type_Descriptor";
	private static final String CLASS = "class";
	private static final String GUARD_FUNCTION = "_guard_check_icall";
	private static final String CFG_WARNING =
		"Control Flow Guard (CFG) detected. Vftables not analyzed.";

	private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();
	private WindowsVftableAnalysisCmd vfTableAnalyzer;

	public WindowsCppClassAnalyzer() {
		super(NAME);
		setPriority(new RttiAnalyzer().getPriority().after());
	}

	@SuppressWarnings("hiding")
	@Override
	public boolean canAnalyze(Program program) {
		return PEUtil.canAnalyze(program) && !GnuUtils.isGnuCompiler(program);
	}

	private boolean hasGuardedVftables() {
		FunctionManager manager = program.getFunctionManager();
		for (Function function : manager.getFunctions(true)) {
			if (function.getName().equals(GUARD_FUNCTION)) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected boolean hasVtt() {
		return false;
	}

	public static List<ClassTypeInfo> getClassTypeInfoList(Program program, TaskMonitor monitor)
			throws CancelledException {
		final ArrayList<ClassTypeInfo> classes = new ArrayList<>();
		final SymbolTable table = program.getSymbolTable();
		final AddressSet addrSet = new AddressSet();
		GnuUtils.getAllDataBlocks(program).forEach(
			(b)->addrSet.addRange(b.getStart(), b.getEnd()));
		List<Symbol> symbols = StreamSupport.stream(
			table.getSymbols(addrSet, SymbolType.LABEL, true)
				 .spliterator(), false)
				 .filter((s)->s.getName().contains(SYMBOL_NAME))
				 .collect(Collectors.toList());
		monitor.initialize(symbols.size());
		monitor.setMessage("Locating Type Information");
        for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			TypeDescriptorModel descriptor = new TypeDescriptorModel(
				program, symbol.getAddress(), DEFAULT_OPTIONS);
			try {
				if (!descriptor.getRefType().equals(CLASS)) {
					monitor.incrementProgress(1);
					continue;
				}
				descriptor.validate();
			} catch (InvalidDataTypeException | NullPointerException e) {
				monitor.incrementProgress(1);
				continue;
			}
			ClassTypeInfo type = RttiModelWrapper.getWrapper(descriptor);
			if (type == null) {
				try {
					Msg.debug(WindowsCppClassAnalyzer.class, descriptor.getTypeName());
				} catch (InvalidDataTypeException e2) {
					// I really hate this exception
				}
			} else if (type.getNamespace() != null) {
					classes.add(type);
			}
			monitor.incrementProgress(1);
        }
        classes.trimToSize();
        return classes;
    }

    @Override
    protected List<ClassTypeInfo> getClassTypeInfoList() throws CancelledException {
        return getClassTypeInfoList(program, getMonitor());
    }

    @Override
    protected void analyzeVftables() throws Exception {
        if (!hasGuardedVftables()) {
            super.analyzeVftables();
        } else {
            if (shouldAnalyzeConstructors()) {
                analyzeConstructors(getClassTypeInfoList());
            }
            log.appendMsg(CFG_WARNING);
        }
    }

    @Override
    protected boolean analyzeVftable(ClassTypeInfo type) {
        vfTableAnalyzer.setTypeInfo(type);
        return vfTableAnalyzer.applyTo(program);
    }

    @Override
    protected boolean analyzeConstructor(ClassTypeInfo type) {
       constructorAnalyzer.setTypeInfo(type);
       return constructorAnalyzer.applyTo(program);
    }

    @Override
    protected AbstractConstructorAnalysisCmd getConstructorAnalyzer() {
        this.vfTableAnalyzer = new WindowsVftableAnalysisCmd();
        return new WindowsConstructorAnalysisCmd();
    }

    @Override
    protected boolean isDestructor(Function function) {
        return function.getName().contains("destructor");
    }

}
