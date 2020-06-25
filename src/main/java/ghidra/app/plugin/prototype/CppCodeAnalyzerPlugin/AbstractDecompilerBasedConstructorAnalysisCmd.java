package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin;

import java.util.List;
import java.util.Map;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.AssertException;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.decompiler.HighThisParameterValue;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public abstract class AbstractDecompilerBasedConstructorAnalysisCmd
		extends AbstractConstructorAnalysisCmd {

	private final DecompilerAPI api;

	protected AbstractDecompilerBasedConstructorAnalysisCmd(String name, DecompilerAPI api) {
		super(name);
		this.api = api;
	}

	protected AbstractDecompilerBasedConstructorAnalysisCmd(String name, ClassTypeInfo typeinfo,
			DecompilerAPI api) {
		super(name, typeinfo);
		this.api = api;
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
				List<ClangStatement> statements = api.getClangStatements(function.getFunction());
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
		private final ClangStatement statement;

		FunctionCallParser(ClangStatement statement) throws IllegalArgumentException {
			this.statement = statement;
			if (statement.Child(0) instanceof ClangFuncNameToken) {
				this.name = (ClangFuncNameToken) statement.Child(0);
			} else {
				throw new IllegalArgumentException(
					"Clang token group must contain a function call\n"
					+ statement.toString());
			}
		}

		Function getCalledFunction() {
			return api.getFunction(name);
		}

		ClassTypeInfo getParentParameter() {
			HighThisParameterValue value = new HighThisParameterValue(statement);
			if (value.getParam() == null) {
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

}
