package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.app.plugin.prototype.GnuRttiAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.COMPILER_NAMES;

public class GccCppClassAnalyzer extends AbstractCppClassAnalyzer {

    private static final String NAME = "GCC C++ Class Analyzer";

    public GccCppClassAnalyzer() {
        super(NAME);
        setPriority(new GnuRttiAnalyzer().getPriority().after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
        return COMPILER_NAMES.contains(id);
    }

    @Override
    protected boolean hasVtt() {
        return true;
    }

    @Override
    protected List<ClassTypeInfo> getClassTypeInfoList(Program program) {
		List<ClassTypeInfo> classes = new ArrayList<>();
        SymbolTable table = program.getSymbolTable();
        for (Symbol symbol : table.getSymbols(TypeInfo.SYMBOL_NAME)) {
            TypeInfo type = TypeInfoFactory.getTypeInfo(program, symbol.getAddress());
            if (type instanceof ClassTypeInfo) {
                classes.add((ClassTypeInfo) type);
            }
        }
        return classes;
    }

    @Override
    protected BackgroundCommand getVftableAnalyzer(ClassTypeInfo type) {
        return new GccVtableAnalysisCmd(type);
    }

    @Override
    protected BackgroundCommand getConstructorAnalyzer(Object o) {
        if (o instanceof VttModel) {
            return new GccConstructorAnalysisCmd((VttModel) o);
        }
        return new GccConstructorAnalysisCmd((ClassTypeInfo) o);
	}

    
}
