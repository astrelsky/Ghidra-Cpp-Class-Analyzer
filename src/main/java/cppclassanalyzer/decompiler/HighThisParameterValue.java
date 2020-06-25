package cppclassanalyzer.decompiler;

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.Msg;

public final class HighThisParameterValue {

	private final HighParam param;
	private final ClangOpToken op;
	private final HighConstant value;

	public HighThisParameterValue(ClangStatement statement) {
		this(getNodes(statement));
	}

	private static List<ClangNode> getNodes(ClangStatement statement) {
		List<ClangNode> children = new ArrayList<>(statement.numChildren());
		statement.flatten(children);
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

	private HighThisParameterValue(List<ClangNode> inNodes) {
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

	public int getOffset() {
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

	public HighParam getParam() {
		return param;
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

	public static HighConstant getConstant(ClangNode node) {
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
