package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers.WindowsClassTypeInfo;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public class WindowsVftableAnalysisCmd extends BackgroundCommand {

	private static final String NAME = WindowsVftableAnalysisCmd.class.getSimpleName();


	private ClassTypeInfo type;
	private TaskMonitor monitor;

	protected WindowsVftableAnalysisCmd() {
		super(NAME, false, true, false);
	}

	public WindowsVftableAnalysisCmd(ClassTypeInfo type) {
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
		}
		return true;
	}

	private static boolean isPureVirtual(Function f) {
		return f.getName().equals(WindowsClassTypeInfo.PURE_VIRTUAL_FUNCTION_NAME);
	}

	private void setupFunctions(Vtable vftable) throws CancelledException {
		Function[][] functionTables = vftable.getFunctionTables();
		for (Function[] functionTable : functionTables) {
			monitor.checkCanceled();
			for (Function f : functionTable) {
				monitor.checkCanceled();
				if (!CppClassAnalyzerUtils.isDefaultFunction(f) || isPureVirtual(f)) {
					continue;
				}
				CppClassAnalyzerUtils.createThunkFunctions(f);
				ClassTypeInfoUtils.setClassFunction(type, f);
			}
		}
	}

}
