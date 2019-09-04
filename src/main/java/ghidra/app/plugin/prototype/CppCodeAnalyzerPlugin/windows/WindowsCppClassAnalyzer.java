package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsVftableAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.TypeDescriptorModelWrapper;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.RttiAnalyzer;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class WindowsCppClassAnalyzer extends AbstractCppClassAnalyzer {

    private static final String NAME = "Windows C++ Class Analyzer";
    private static final String SYMBOL_NAME = "RTTI_Type_Descriptor";

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
                ClassTypeInfo type =
                    new TypeDescriptorModelWrapper(program, symbol.getAddress());
                if (type.isValid()) {
                    classes.add(type);
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
