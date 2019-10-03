package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsVftableAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

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
        return PEUtil.canAnalyze(program);
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

    @Override
    protected List<ClassTypeInfo> getClassTypeInfoList() {
        ArrayList<ClassTypeInfo> classes = new ArrayList<>();
        SymbolTable table = program.getSymbolTable();
        for (Symbol symbol : table.getAllSymbols(false)) {
            if (symbol.getName().contains(SYMBOL_NAME)) {
                TypeDescriptorModel descriptor = new TypeDescriptorModel(program, symbol.getAddress(), DEFAULT_OPTIONS);
                try {
                    if (!descriptor.getRefType().equals(CLASS)) {
                        continue;
                    }
                    descriptor.validate();
                } catch (InvalidDataTypeException | NullPointerException e) {
                    continue;
                }
                ClassTypeInfo type = new RttiModelWrapper(descriptor);
                try {
                    type.validate();
                    if (type.getNamespace() != null) {
                        classes.add(type);
                    }
                } catch (InvalidDataTypeException e) {
                    continue;
                }
            }
        }
        classes.trimToSize();
        return classes;
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
