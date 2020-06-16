package cppclassanalyzer.decompiler;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class FunctionCallAnalysisTask extends Task {

	private static final String TITLE = FunctionCallAnalysisTask.class.getSimpleName();

	private final Function function;
	private final int timeout;
	private List<FunctionCallAnalysisResult> results;

	public FunctionCallAnalysisTask(Function function, boolean canCancel,
			boolean isModal, boolean waitForTaskCompleted) {
		this(function, canCancel, isModal, waitForTaskCompleted, 0);
	}

	public FunctionCallAnalysisTask(Function function, boolean canCancel,
			boolean isModal, boolean waitForTaskCompleted, int timeout) {
		super(TITLE, canCancel, isModal, waitForTaskCompleted);
		this.function = Objects.requireNonNull(function);
		this.timeout = timeout;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		this.results = DecompilerUtils.getClangStatements(function, monitor)
			.stream()
			.map(FunctionCallAnalysisResult::new)
			.collect(Collectors.toList());
	}

	public List<FunctionCallAnalysisResult> getResults() {
		return results;
	}

	public final class FunctionCallAnalysisResult {

		private final ClangStatement statement;

		private FunctionCallAnalysisResult(ClangStatement statement) {
			this.statement = statement;
		}

		private ClangFuncNameToken getFuncNameToken() {
			return (ClangFuncNameToken) statement.Child(0);
		}

		public String getFunctionName() {
			return getFuncNameToken().toString();
		}

		public Address getAddress() {
			return getFuncNameToken().getMaxAddress();
		}

		public Function getFunction() {
			Program program = function.getProgram();
			return DecompilerUtils.getFunction(program, getFuncNameToken());
		}
	}

}