package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;

public class WindowsVftableAnalysisCmd extends BackgroundCommand {

	private static final String NAME = WindowsVftableAnalysisCmd.class.getSimpleName();


	private ClassTypeInfo typeinfo;

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
		try {
			Vtable vtable = typeinfo.getVtable();
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

	private void setupFunctions(Vtable vftable) {
		ClassTypeInfo type = vftable.getTypeInfo();
		Consumer<Function> typeSetter = f -> ClassTypeInfoUtils.setClassFunction(type, f);
		Function[][] functionTables = vftable.getFunctionTables();
		Arrays.stream(functionTables)
			.flatMap(Arrays::stream)
			.filter(Objects::nonNull)
			.filter(CppClassAnalyzerUtils::isDefaultFunction)
			.map(CppClassAnalyzerUtils::createThunkFunctions)
			.forEach(typeSetter);
	}

}