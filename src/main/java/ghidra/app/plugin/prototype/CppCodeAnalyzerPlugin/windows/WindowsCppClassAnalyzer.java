package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsVftableAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.RttiModelWrapper;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class WindowsCppClassAnalyzer extends AbstractCppClassAnalyzer {

    private static final String NAME = "Windows C++ Class Analyzer";
    private static final String SYMBOL_NAME = "RTTI_Type_Descriptor";
    private static final String CLASS = "class";
    private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

    public WindowsCppClassAnalyzer() {
        super(NAME);
        setPriority(new RttiAnalyzer().getPriority().after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return PEUtil.canAnalyze(program);
    }

    @Override
    protected boolean hasVtt() {
        return false;
    }

    @Override
    protected List<ClassTypeInfo> getClassTypeInfoList(Program program) {
		ArrayList<ClassTypeInfo> classes = new ArrayList<>();
        SymbolTable table = program.getSymbolTable();
        for (Symbol symbol : table.getAllSymbols(false)) {
            if (symbol.getName().contains(SYMBOL_NAME)) {
                TypeDescriptorModel descriptor =
                    new TypeDescriptorModel(program, symbol.getAddress(), DEFAULT_OPTIONS);
                try {
                    if (!descriptor.getRefType().equals(CLASS)) {
                        continue;
                    }
                    descriptor.validate();
                } catch (InvalidDataTypeException | NullPointerException e) {
                    continue;
                }
                ClassTypeInfo type =
                    new RttiModelWrapper(descriptor);
                try {
                    type.validate();
                    classes.add(type);
                } catch (InvalidDataTypeException e) {
                    continue;
                }
            }
        }
        classes.trimToSize();
        return classes;
    }

    @Override
    protected BackgroundCommand getVftableAnalyzer(ClassTypeInfo type) {
        return new WindowsVftableAnalysisCmd(type);
    }

    @Override
    protected BackgroundCommand getConstructorAnalyzer(Object o) {
        return new WindowsConstructorAnalysisCmd((ClassTypeInfo) o);
	}
    
}
