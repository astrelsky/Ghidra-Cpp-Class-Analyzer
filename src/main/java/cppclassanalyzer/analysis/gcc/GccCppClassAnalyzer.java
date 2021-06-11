package cppclassanalyzer.analysis.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.GccRttiAnalyzer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import cppclassanalyzer.analysis.AbstractCppClassAnalyzer;
import cppclassanalyzer.decompiler.DecompilerAPI;

import static ghidra.app.cmd.data.rtti.gcc.GnuUtils.isGnuCompiler;

public class GccCppClassAnalyzer extends AbstractCppClassAnalyzer {

	public static final String ANALYZER_NAME = "GCC C++ Class Analyzer";
	private DecompilerAPI api;
	private GccVtableAnalysisCmd vtableAnalyzer;

	public GccCppClassAnalyzer() {
		super(ANALYZER_NAME);
		setPriority(new GccRttiAnalyzer().getPriority().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return super.canAnalyze(program) && isGnuCompiler(program);
	}

	@Override
	protected boolean hasVtt() {
		return true;
	}

	@Override
	protected void init() {
		this.vtableAnalyzer = new GccVtableAnalysisCmd();
		this.api = getDecompilerAPI(program);
		api.setMonitor(monitor);
		api.setTimeout(getTimeout());
		this.constructorAnalyzer = new GccDecompilerConstructorAnalysisCmd(api);
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
		if (!Vtable.isValid(vtable)) {
			// can only analyze types with valid vtables
			return false;
		}
		//VttModel vtt = VtableUtils.getVttModel(program, (GnuVtable) vtable);
		constructorAnalyzer.setTypeInfo(type);
		return constructorAnalyzer.applyTo(program);
	}
}
