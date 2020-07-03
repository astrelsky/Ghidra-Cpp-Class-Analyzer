package cppclassanalyzer.decompiler.function;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;

import cppclassanalyzer.decompiler.token.ClangNodeUtils;

public final class HighFunctionCallParameter {

	private final HighFunction hf;
	private final ClangTokenGroup group;

	HighFunctionCallParameter(HighFunction hf, ClangTokenGroup group) {
		this.hf = hf;
		this.group = group;
	}

	private <T extends ClangNode> boolean hasNode(Class<T> clazz) {
		return ClangNodeUtils.asStream(group)
			.anyMatch(clazz::isInstance);
	}

	private <T extends ClangNode> T getFirstNode(Class<T> clazz) {
		return ClangNodeUtils.asStream(group)
			.filter(clazz::isInstance)
			.map(clazz::cast)
			.findFirst()
			.orElse(null);
	}

	private <T extends ClangToken> List<T> getTokens(Class<T> clazz) {
		return ClangNodeUtils.asStream(group)
			.filter(clazz::isInstance)
			.map(clazz::cast)
			.collect(Collectors.toList());
	}

	public ClangVariableToken getVariableToken() {
		return getFirstNode(ClangVariableToken.class);
	}

	public boolean hasFieldToken() {
		return hasNode(ClangFieldToken.class);
	}

	public ClangFieldToken getFieldToken() {
		return getFirstNode(ClangFieldToken.class);
	}

	public boolean hasLocalRef() {
		ClangVariableToken token = getVariableToken();
		if (token == null) {
			return false;
		}
		HighVariable var = token.getHighVariable();
		if (var == null) {
			return false;
		}
		return hf.getLocalSymbolMap().containsVariableWithName(var.getName());
	}

	public boolean hasGlobalRef() {
		HighVariable var = getVariableToken().getHighVariable();
		if (var == null) {
			return false;
		}
		return var.getSymbol().isGlobal();
	}

	public List<ClangOpToken> getOpTokens() {
		return getTokens(ClangOpToken.class);
	}

	public List<ClangNode> getTokens() {
		List<ClangNode> tokens = new ArrayList<>(group.numChildren());
		group.flatten(tokens);
		return tokens;
	}

	public int getOffset() {
		ClangVariableToken var = getVariableToken();
		PcodeOp op = var.getPcodeOp();
		if (op.getOpcode() == PcodeOp.PTRADD) {
			Varnode index = op.getInput(1);
			Scalar value = ((HighConstant) index.getHigh()).getScalar();
			return var.getHighVariable().getDataType().getLength()
				* (int) value.getValue();
		}
		return 0;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		for (ClangNode node : ClangNodeUtils.asIterable(group)) {
			builder.append(((ClangToken) node).getText());
		}
		return builder.toString();
	}

}
