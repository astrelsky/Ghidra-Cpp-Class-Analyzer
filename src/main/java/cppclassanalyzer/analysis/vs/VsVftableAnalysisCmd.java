package cppclassanalyzer.analysis.vs;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import cppclassanalyzer.vs.VsVtableModel;

public class VsVftableAnalysisCmd extends BackgroundCommand {

	private ClassTypeInfo type;
	private TaskMonitor monitor;

	protected VsVftableAnalysisCmd() {
		super(VsVftableAnalysisCmd.class.getSimpleName(), false, true, false);
	}

	public VsVftableAnalysisCmd(ClassTypeInfo type) {
		this();
		this.type = type;
	}

	public void setTypeInfo(ClassTypeInfo type) {
		this.type = type;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if (!(obj instanceof Program)) {
			String message = "Can only analyze a vtable in a program.";
			Msg.error(this, message);
			return false;
		}
		this.monitor = monitor;
		try {
			Vtable vtable = type.getVtable();
			if (!Vtable.isValid(vtable)) {
				return false;
			}
			setupFunctions(vtable);
			return true;
		} catch (Exception e) {
			Msg.error(this, e);
			e.printStackTrace();
		}
		return true;
	}

	private static boolean isPureVirtual(Function f) {
		return f.getName().equals(VsVtableModel.PURE_VIRTUAL_FUNCTION_NAME);
	}

	private void setupFunctions(Vtable vftable) throws CancelledException {
		Function[][] functionTables = vftable.getFunctionTables();
		for (Function[] functionTable : functionTables) {
			monitor.checkCancelled();
			for (Function f : functionTable) {
				monitor.checkCancelled();
				CppClassAnalyzerUtils.createThunkFunctions(f);
				while (f.isThunk()) {
					f = f.getThunkedFunction(true);
				}
				if (f.isExternal()) {
					continue;
				}
				if (!CppClassAnalyzerUtils.isDefaultFunction(f) || isPureVirtual(f)) {
					continue;
				}
				ClassTypeInfoUtils.setClassFunction(type, f);
			}
		}
	}

}
