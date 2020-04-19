package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.getClassFunction;
import static ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.VftableAnalysisUtils.isProcessedFunction;

public class WindowsVftableAnalysisCmd extends BackgroundCommand {

	private static final String NAME = WindowsVftableAnalysisCmd.class.getSimpleName();


	private ClassTypeInfo typeinfo;
	private Program program;

	protected WindowsVftableAnalysisCmd() {
		super(NAME, false, true, false);
	}

	public WindowsVftableAnalysisCmd(ClassTypeInfo type) {
		this();
		this.typeinfo = type;
	}

	public void setTypeInfo(ClassTypeInfo type) {
		this.typeinfo = type;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if (!(obj instanceof Program)) {
			String message = "Can only analyze a vtable in a program.";
			Msg.error(this, message);
			return false;
		}
		this.program = (Program) obj;
		try {
			Vtable vtable = typeinfo.getVtable();
			setupFunctions(vtable);
			return true;
		} catch (Exception e) {
			Msg.error(this, e);
		}
		return true;
	}
	
	private void setupFunctions(Vtable vftable) throws Exception {
		ClassTypeInfo type = vftable.getTypeInfo();
		Function[][] functionTables = vftable.getFunctionTables();
		for (Function[] functionTable : functionTables) {
			for (Function function : functionTable) {
				if (!isProcessedFunction(function)) {
					Function thunkedFunction =
						VftableAnalysisUtils.recurseThunkFunctions(program, function);
					if (!isProcessedFunction(thunkedFunction)) {
						getClassFunction(program, type, thunkedFunction.getEntryPoint());
					}
				}
			}
		}
	}

}