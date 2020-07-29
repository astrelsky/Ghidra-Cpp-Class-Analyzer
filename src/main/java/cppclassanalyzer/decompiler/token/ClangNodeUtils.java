package cppclassanalyzer.decompiler.token;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.pcode.PcodeOp;

import cppclassanalyzer.decompiler.function.HighFunctionCall;

public final class ClangNodeUtils {

	private ClangNodeUtils() {
	}

	public static Stream<ClangNode> asStream(ClangTokenGroup group) {
		return IntStream.range(0, group.numChildren())
			.mapToObj(group::Child);
	}

	public static Stream<ClangNode> asFlatStream(ClangTokenGroup group) {
		FlatNodeMapper mapper = new FlatNodeMapper(group);
		return IntStream.range(0, group.numChildren())
			.mapToObj(mapper::flatten)
			.flatMap(Objects::requireNonNull);
	}

	public static Iterator<ClangNode> asIterator(ClangTokenGroup group) {
		return asStream(group)
			.iterator();
	}

	public static Iterator<ClangNode> asFlatIterator(ClangTokenGroup group) {
		return asFlatStream(group)
			.iterator();
	}

	public static Iterable<ClangNode> asIterable(ClangTokenGroup group) {
		return () -> asIterator(group);
	}

	public static Iterable<ClangNode> asFlatIterable(ClangTokenGroup group) {
		return () -> asFlatIterator(group);
	}

	private static Stream<ClangStatement> getStatementStream(ClangTokenGroup group) {
		return asFlatStream(group)
			.filter(ClangStatement.class::isInstance)
			.map(ClangStatement.class::cast);
	}

	public static List<ClangStatement> getClangStatements(ClangTokenGroup group) {
		return getStatementStream(group)
			.collect(Collectors.toList());
	}

	public static List<HighFunctionCall> getClangFunctionCalls(ClangTokenGroup group) {
		return getStatementStream(group)
			.filter(ClangNodeUtils::isCallStatement)
			.map(HighFunctionCall::getHighFunctionCall)
			.filter(Objects::nonNull)
			.sorted()
			.collect(Collectors.toList());
	}

	public static ClangLine getClangLine(ClangTokenGroup group, int line) {
		return getClangLines(group)
			.stream()
			.filter(l -> l.getLineNumber() == line)
			.findFirst()
			.orElse(null);
	}

	public static List<ClangLine> getClangLines(ClangTokenGroup group) {
		return DecompilerUtils.toLines(group);
	}

	///////////////////////////////////////////////////////////////////////////
	//                             Filters                                   //
	///////////////////////////////////////////////////////////////////////////

	public static boolean isClangTokenGroup(ClangNode node) {
		return node.getClass() == ClangTokenGroup.class;
	}

	private static boolean isCallStatement(ClangStatement statement) {
		PcodeOp op = statement.getPcodeOp();
		return op != null ? op.getOpcode() == PcodeOp.CALL : false;
	}

	///////////////////////////////////////////////////////////////////////////
	//                           Comparitors                                 //
	///////////////////////////////////////////////////////////////////////////

	public static int compareClangLines(ClangLine lineA, ClangLine lineB) {
		return Integer.compare(lineA.getLineNumber(), lineB.getLineNumber());
	}

	private static class FlatNodeMapper {

		private final ClangTokenGroup group;

		FlatNodeMapper(ClangTokenGroup group) {
			this.group = group;
		}

		Stream<ClangNode> flatten(int i) {
			ClangNode node = group.Child(i);
			if (isClangTokenGroup(node)) {
				return asFlatStream((ClangTokenGroup) node);
			}
			return Stream.of(node);
		}
	}
}
