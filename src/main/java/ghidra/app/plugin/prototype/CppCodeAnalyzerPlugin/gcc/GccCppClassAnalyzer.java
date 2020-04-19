package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.VtableUtils;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.plugin.prototype.GccRttiAnalyzer;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractConstructorAnalysisCmd;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractCppClassAnalyzer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.isGnuCompiler;

public class GccCppClassAnalyzer extends AbstractCppClassAnalyzer {

	private static final String NAME = "GCC C++ Class Analyzer";
	private GccVtableAnalysisCmd vtableAnalyzer;

	public GccCppClassAnalyzer() {
		super(NAME);
		setPriority(new GccRttiAnalyzer().getPriority().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isGnuCompiler(program);
	}

	@Override
	protected boolean hasVtt() {
		return true;
	}

	@Override
	protected AbstractConstructorAnalysisCmd getConstructorAnalyzer() {
		this.vtableAnalyzer = new GccVtableAnalysisCmd();
		return new GccConstructorAnalysisCmd();
	}

	@Override
	protected boolean isDestructor(Function function) {
		return function.getName().startsWith("~");
	}

	@Override
	protected boolean analyzeVftable(ClassTypeInfo type) {
		vtableAnalyzer.setTypeInfo(type);
		return vtableAnalyzer.applyTo(program);
	}

	@Override
	protected boolean analyzeConstructor(ClassTypeInfo type) {
		Vtable vtable = type.getVtable();
		VttModel vtt = VtableUtils.getVttModel(program, vtable);
		if (vtt.isValid()) {
			((GccConstructorAnalysisCmd) constructorAnalyzer).setVtt(vtt);
		} else {
			constructorAnalyzer.setTypeInfo(type);
		}
		return constructorAnalyzer.applyTo(program);
	}
}
