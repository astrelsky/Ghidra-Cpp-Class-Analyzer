package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.decompiler.DecompilerUtils;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public abstract class AbstractDecompilerBasedConstructorAnalysisCmd
		extends AbstractConstructorAnalysisCmd {

	private final int timeout;

	protected AbstractDecompilerBasedConstructorAnalysisCmd(String name, int timeout) {
		super(name);
		this.timeout = timeout;
	}

	protected AbstractDecompilerBasedConstructorAnalysisCmd(String name, ClassTypeInfo typeinfo,
			int timeout) {
		super(name, typeinfo);
		this.timeout = timeout;
	}

	@Override
	protected boolean analyze() throws Exception {
		if (!type.hasParent()) {
			return false;
		}
		for (ClassFunction function : getFunctions()) {
			monitor.checkCanceled();
			FunctionSignature signature = function.getFunction().getSignature();
			SourceType source = function.getFunction().getSignatureSource();
			boolean success = false;
			try {
				setFunction(type, function.getFunction(), function.isDestructor());
				List<ClangStatement> statements =
					DecompilerUtils.getClangStatements(function.getFunction(), monitor, timeout);
				if (type.getParentModels().length >= statements.size()) {
					continue;
				}
				if (function.isDestructor()) {
					success = processDestructor(function.getFunction(), statements);
				} else {
					success = processConstructor(function.getFunction(), statements);
				}
			} finally {
				if (!success) {
					ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
						function.getFunction().getEntryPoint(), signature, source, false, true);
					cmd.applyTo(program);
				}
			}
		}
		return true;
	}

	private boolean processDestructor(Function function, List<ClangStatement> statements)
			throws Exception {
		// The in-charge destructor must end with all
		// parents destructors + return. No exceptions.
		ClassTypeInfo[] parents = type.getParentModels();
		int end = statements.size() - 1;
		int start = end - parents.length;
		List<ClangStatement> destructorCalls = statements.subList(start, end);
		if (destructorCalls.size() != parents.length) {
			throw new AssertException("Start and end indexes aren't correct");
		}
		return setFunctions(destructorCalls, false);
	}

	private boolean processConstructor(Function function, List<ClangStatement> statements)
			throws Exception {
		// The in-charge constructor must start with all
		// parents constructors. No exceptions.
		ClassTypeInfo[] parents = type.getParentModels();
		int start = 0;
		int end = parents.length;
		List<ClangStatement> constructorCalls = statements.subList(start, end);
		if (constructorCalls.size() != parents.length) {
			throw new AssertException("Start and end indexes aren't correct");
		}
		return setFunctions(constructorCalls, true);
	}

	private boolean setFunctions(List<ClangStatement> statements, boolean isConstructor)
			throws Exception {
		for (ClangStatement statement : statements) {
			if (!(statement.Child(0) instanceof ClangFuncNameToken)) {
				return false;
			}
			FunctionCallParser parser = new FunctionCallParser(statement);
			Function fun = parser.getCalledFunction();
			ClassTypeInfo parent = parser.getParentParameter();
			if (parent == null) {
				String msg = String.format(
					"Base class for %s not found in statement %s",
					type,
					statement);
				Msg.warn(this, msg);
				return false;
			}
			ClassTypeInfoUtils.setClassFunction(parent, fun);
			CppClassAnalyzerUtils.setConstructorDestructorTag(fun, isConstructor);
			String fName = isConstructor ? parent.getName() : '~' + parent.getName();
			fun.setName(fName, SourceType.USER_DEFINED);
		}
		return true;
	}

	protected abstract List<ClassFunction> getFunctions();

	protected static class ClassFunction {

		private final Function function;
		private final boolean isDestructor;

		public ClassFunction(Function function, boolean isDestructor) {
			this.function = function;
			this.isDestructor = isDestructor;
		}

		protected Function getFunction() {
			return function;
		}

		protected boolean isDestructor() {
			return isDestructor;
		}
	}

	private final class FunctionCallParser {

		private final ClangFuncNameToken name;
		private final List<ClangNode> children;

		FunctionCallParser(ClangTokenGroup group) throws IllegalArgumentException {
			this.children = new ArrayList<>(group.numChildren());
			group.flatten(children);
			if (children.get(0) instanceof ClangFuncNameToken) {
				this.name = (ClangFuncNameToken) children.get(0);
			} else {
				throw new IllegalArgumentException(
					"Clang token group must contain a function call\n"
					+ group.toString());
			}
		}

		Function getCalledFunction() {
			return DecompilerUtils.getFunction(program, name);
		}

		List<ClangNode> getParentParameterNodes() {
			int start = 0;
			int end = 0;
			for (; start < children.size(); start++) {
				ClangNode node = children.get(start);
				if (node instanceof ClangVariableToken) {
					HighVariable var = ((ClangVariableToken) node).getHighVariable();
					if (!(var instanceof HighParam)) {
						return Collections.emptyList();
					}
					if (((HighParam) var).getSlot() != 0) {
						return Collections.emptyList();
					}
					break;
				}
			}
			if (start == children.size()) {
				return Collections.emptyList();
			}
			for (end = start + 1; end < children.size(); end++) {
				ClangNode node = children.get(end);
				if (node.toString().equals(",") || node.toString().equals(")")) {
					break;
				}
			}
			return children.subList(start, end);
		}

		ClassTypeInfo getParentParameter() {
			HighParameterValue value = new HighParameterValue(getParentParameterNodes());
			if (value.param == null) {
				return null;
			}
			int offset = value.getOffset();
			if (offset == -1) {
				return null;
			}
			ClassTypeInfoDB db = (ClassTypeInfoDB) type;
			return db.getBaseOffsets()
				.entrySet()
				.stream()
				.filter(e -> e.getValue().intValue() == offset)
				.findFirst()
				.map(Map.Entry::getKey)
				.orElse(null);
		}
	}

	private static class HighParameterValue {

		private final HighParam param;
		private final ClangOpToken op;
		private final HighConstant value;

		HighParameterValue(List<ClangNode> inNodes) {
			List<ClangNode> nodes = new ArrayList<>(inNodes);
			nodes.removeIf(n -> n.toString().equals(" "));
			Iterator<ClangNode> it = nodes.iterator();
			ClangNode node = null;
			if (it.hasNext()) {
				node = it.next();
			}
			this.param = getParam(node);
			if (it.hasNext()) {
				node = it.next();
			}
			this.op = getOpToken(node);
			if (it.hasNext()) {
				node = it.next();
			}
			this.value = getConstant(node);
		}

		int getOffset() {
			if (op == null) {
				return param != null ? 0 : -1;
			}
			if (value == null) {
				return -1;
			}
			int offset = (int) value.getScalar().getUnsignedValue();
			switch (op.toString().charAt(0)) {
				case '+':
				case '[':
					int size = param.getDataType().getLength();
					return size * offset;
				default:
					Msg.warn(this, "Unexpected op: "+op.toString());
					return -1;
			}
		}

		private static HighParam getParam(ClangNode node) {
			if (node instanceof ClangVariableToken) {
				HighVariable var = ((ClangVariableToken) node).getHighVariable();
				if (var instanceof HighParam) {
					return (HighParam) var;
				}
			}
			return null;
		}

		private static ClangOpToken getOpToken(ClangNode node) {
			if (node instanceof ClangOpToken) {
				return (ClangOpToken) node;
			}
			return null;
		}

		private static HighConstant getConstant(ClangNode node) {
			if (node instanceof ClangVariableToken) {
				HighVariable var =
					(HighVariable) ((ClangVariableToken) node).getHighVariable();
				if (var instanceof HighConstant) {
					return (HighConstant) var;
				}
			}
			return null;
		}
	}

}