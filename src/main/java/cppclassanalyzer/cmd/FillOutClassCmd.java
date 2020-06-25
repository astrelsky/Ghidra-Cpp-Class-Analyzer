package cppclassanalyzer.cmd;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.decompiler.DecompilerUtils;
import cppclassanalyzer.decompiler.HighThisParameterValue;

public final class FillOutClassCmd extends BackgroundCommand {

	private final DecompilerActionContext context;
	private final ClassTypeInfoDB type;

	public FillOutClassCmd(DecompilerActionContext context) {
		this.context = context;
		ClassTypeInfoManagerService service =
			context.getTool().getService(ClassTypeInfoManagerService.class);
		ProgramClassTypeInfoManager manager =
			service.getManager(context.getFunction().getProgram());
		this.type = manager.getType(context.getFunction());
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		try {
			monitor.checkCanceled();
			doApplyTo(monitor);
			return true;
		} catch (CancelledException e) {
			setStatusMsg(e.getLocalizedMessage());
		}
		return false;
	}

	private ProgramClassTypeInfoManager getManager() {
		return (ProgramClassTypeInfoManager) type.getManager();
	}

	private void doApplyTo(TaskMonitor monitor) throws CancelledException {
		List<ClangStatement> statements =
			DecompilerUtils.getClangStatements(context.getCCodeModel());
		monitor.setMessage("Analyzing "+type.getName()+" member usage");
		monitor.initialize(statements.size());
		for (ClangStatement statement : statements) {
			monitor.checkCanceled();
			HighThisParameterValue value = new HighThisParameterValue(statement);
			if (value.getParam() != null && value.getOffset() >= 0) {
				Function fun = DecompilerUtils.getFunction(
					context.getProgram(), (ClangFuncNameToken) statement.Child(0));
				if (fun != null) {
					setMember(fun, value);
				}
			}
			monitor.incrementProgress(1);
		}
	}

	private void setMember(Function fun, HighThisParameterValue value) {
		ClassTypeInfoDB member = getManager().getType(fun);
		if (member == null) {
			return;
		}
		int offset = value.getOffset();
		Structure struct = type.getClassDataType();
		DataTypeComponent comp = struct.getComponentAt(offset);
		while (comp != null) {
			DataType dt = comp.getDataType();
			if (!(dt instanceof Structure)) {
				// don't replace user defined components
				return;
			}
			offset -= comp.getOffset();
			struct = (Structure) dt;
			comp = struct.getComponent(offset);
		}
		DataType memberDt = member.getClassDataType();
		String name = createMemberName(memberDt, struct, offset);
		struct.replaceAtOffset(offset, memberDt, memberDt.getLength(), name, null);
	}

	private static String createMemberName(DataType dt, Structure struct, int offset) {
		String name = dt.getName();
		if (Character.isUpperCase(name.charAt(0))) {
			Character C = Character.valueOf(name.charAt(0));
			Character c = Character.valueOf(Character.toLowerCase(C));
			name = name.replaceFirst(C.toString(), c.toString());
		}
		boolean exists = Arrays.stream(struct.getDefinedComponents())
			.map(DataTypeComponent::getFieldName)
			.filter(Objects::nonNull)
			.anyMatch(name::equals);
		if (exists) {
			name += "_" + Integer.toString(offset);
		}
		return name;
	}

}
