package cppclassanalyzer.cmd;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.decompiler.function.HighFunctionCall;
import cppclassanalyzer.decompiler.function.HighFunctionCallParameter;
import cppclassanalyzer.decompiler.token.ClangNodeUtils;
import cppclassanalyzer.service.ClassTypeInfoManagerService;

/**
 * BackgroundCommand to fill out a ClassTypeInfo's Structure
 */
public final class FillOutClassBackgroundCmd extends BackgroundCommand {

	private final DecompilerActionContext context;
	private final ClassTypeInfoDB type;

	/**
	 * Constructs a new FillOutClassCmd
	 * @param context the decompiler context
	 */
	public FillOutClassBackgroundCmd(DecompilerActionContext context) {
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
		List<HighFunctionCall> calls =
			ClangNodeUtils.getClangFunctionCalls(context.getCCodeModel());
		monitor.setMessage("Analyzing "+type.getName()+" member usage");
		monitor.initialize(calls.size());
		for (HighFunctionCall call : calls) {
			monitor.checkCanceled();
			analyzeCall(call);
			monitor.incrementProgress(1);
		}
		// TODO do _vptr assignments too
	}

	private void analyzeCall(HighFunctionCall call) {
		List<HighFunctionCallParameter> params = call.getParameters();
		if (params.isEmpty()) {
			return;
		}
		HighFunctionCallParameter self = params.get(0);
		if (!self.hasLocalRef()) {
			return;
		}
		HighVariable var = self.getVariableToken().getHighVariable();
		if (var == null || !var.getName().equals("this")) {
			return;
		}
		final int offset;
		if (self.hasFieldToken()) {
			offset = self.getOffset() + self.getFieldToken().getOffset();
		} else {
			offset = self.getOffset();
		}
		setMember(call.getFunction(), offset);
	}

	private void setMember(Function fun, int offset) {
		ClassTypeInfoDB member = getManager().getType(fun);
		if (member == null) {
			return;
		}
		MemberValidator validator = new MemberValidator(member);
		Structure struct = type.getClassDataType();
		DataTypeComponent comp = struct.getComponentAt(offset);
		while (comp != null) {
			DataType dt = comp.getDataType();
			if (!(dt instanceof Structure)) {
				break;
			}
			if (validator.isInvalidMember(dt)) {
				return;
			}
			offset -= comp.getOffset();
			struct = (Structure) dt;
			if (struct.getNumComponents() == 0 || offset >= struct.getLength()) {
				break;
			}
			comp = struct.getComponent(offset);
		}
		if (comp.getFieldName().startsWith("super_") && offset == 0) {
			return;
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

	private static class MemberValidator {

		private final ClassTypeInfoDB type;

		MemberValidator(ClassTypeInfoDB type) {
			this.type = type;
		}

		boolean isInvalidMember(DataType dt) {
			Structure struct = type.getClassDataType();
			if (dt.isEquivalent(struct)) {
				return true;
			}
			struct = type.getSuperClassDataType();
			return dt.isEquivalent(struct);
		}
	}

}
