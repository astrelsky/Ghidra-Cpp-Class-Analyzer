package cppclassanalyzer.cmd;

import java.util.*;
import java.util.function.Predicate;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.decompiler.function.*;
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
			monitor.checkCancelled();
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
		applyFunctionCalls(monitor);
		applyVptrAssignments(monitor);
	}

	private void applyFunctionCalls(TaskMonitor monitor) throws CancelledException {
		List<HighFunctionCall> calls =
			ClangNodeUtils.getClangFunctionCalls(context.getCCodeModel());
		monitor.setMessage("Analyzing "+type.getName()+" member usage in calls");
		monitor.initialize(calls.size());
		for (HighFunctionCall call : calls) {
			monitor.checkCancelled();
			analyzeCall(call);
			monitor.incrementProgress(1);
		}
	}

	private void applyVptrAssignments(TaskMonitor monitor) throws CancelledException {
		List<ClangStatement> statements = ClangNodeUtils.getClangStatements(context.getCCodeModel());
		statements.removeIf(Predicate.not(FillOutClassBackgroundCmd::isAssignment));
		monitor.setMessage("Analyzing "+type.getName()+" member vptr assignments");
		monitor.initialize(statements.size());
		for (ClangStatement statement : statements) {
			monitor.checkCancelled();
			HighVariableAssignment assignment = new HighVariableAssignment(statement);
			if (assignment.hasGlobalRef() && isThisVariable(assignment)) {
				final int offset;
				if (assignment.hasFieldToken()) {
					offset = assignment.getOffset() + assignment.getFieldToken().getOffset();
				} else {
					offset = assignment.getOffset();
				}
				ClassTypeInfoDB member = getType(assignment);
				if (member != null && !member.equals(type)) {
					setMember(member, offset);
				}
			}
			monitor.incrementProgress(1);
		}
	}

	private ClassTypeInfoDB getType(HighVariableAssignment assignment) {
		Address addr = assignment.getGlobalRefAddress();
		if (addr != null) {
			Program program = getManager().getProgram();
			int ptrSize = program.getDefaultPointerSize();
			Data d = program.getListing().getDataAt(addr.subtract(ptrSize));
			if (d != null && d.isPointer()) {
				return getManager().getType((Address) d.getValue());
			}
		}
		return null;
	}

	private static boolean isAssignment(ClangStatement statement) {
		PcodeOp op = statement.getPcodeOp();
		if (op != null) {
			return op.getOpcode() == PcodeOp.STORE;
		}
		return false;
	}

	private void analyzeCall(HighFunctionCall call) {
		List<HighFunctionCallParameter> params = call.getParameters();
		if (params.isEmpty()) {
			return;
		}
		HighFunctionCallParameter self = params.get(0);
		if (!self.hasLocalRef() || !isThisVariable(self)) {
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

	private boolean isThisVariable(HighStructAccess self) {
		HighVariable var = self.getVariableToken().getHighVariable();
		if (var == null) {
			return false;
		}
		DataType dt = var.getDataType();
		if (!(dt instanceof Pointer)) {
			return false;
		}
		UniversalID id = ((Pointer) dt).getDataType().getUniversalID();
		if (id == null) {
			return false;
		}
		ClassTypeInfoDB member = getManager().getType(id);
		if (member == null || !member.equals(type)) {
			return false;
		}
		return true;
	}

	private void setMember(Function fun, int offset) {
		ClassTypeInfoDB member = getManager().getType(fun);
		if (member != null) {
			setMember(member, offset);
		}
	}

	private void setMember(ClassTypeInfoDB member, int offset) {
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
		if (comp != null && comp.getFieldName() != null) {
			if (comp.getFieldName().startsWith("super_") && offset == 0) {
				return;
			}
		}
		DataType memberDt = member.getClassDataType();
		String name = createMemberName(memberDt, struct, offset);
		if (offset > struct.getLength()) {
			struct.insertAtOffset(offset, memberDt, memberDt.getLength());
		} else {
			struct.replaceAtOffset(offset, memberDt, memberDt.getLength(), name, null);
		}
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
			this.type = Objects.requireNonNull(type);
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
