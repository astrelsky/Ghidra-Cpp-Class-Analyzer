package cppclassanalyzer.decompiler.function;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;

import util.CollectionUtils;

abstract class AbstractHighStructAccess implements HighStructAccess {

	private final List<ClangNode> tokens;

	AbstractHighStructAccess(ClangTokenGroup group) {
		this.tokens = new ArrayList<>(group.numChildren());
		group.flatten(tokens);
	}

	private <T extends ClangNode> boolean hasNode(Class<T> clazz) {
		return tokens.stream()
			.anyMatch(clazz::isInstance);
	}

	private <T extends ClangNode> T getFirstNode(Class<T> clazz) {
		return tokens.stream()
			.filter(clazz::isInstance)
			.map(clazz::cast)
			.findFirst()
			.orElse(null);
	}

	private <T extends ClangToken> List<T> getTokens(Class<T> clazz) {
		return tokens.stream()
			.filter(clazz::isInstance)
			.map(clazz::cast)
			.collect(Collectors.toList());
	}

	@Override
	public final ClangVariableToken getVariableToken() {
		return getFirstNode(ClangVariableToken.class);
	}

	@Override
	public final boolean hasFieldToken() {
		return hasNode(ClangFieldToken.class);
	}

	@Override
	public final ClangFieldToken getFieldToken() {
		return getFirstNode(ClangFieldToken.class);
	}

	@Override
	public final boolean hasLocalRef() {
		ClangVariableToken token = getVariableToken();
		if (token == null) {
			return false;
		}
		HighFunction hf = token.getClangFunction().getHighFunction();
		if (hf == null) {
			return false;
		}
		HighVariable var = token.getHighVariable();
		if (var == null) {
			return false;
		}
		String name = var.getName();
		return CollectionUtils.asStream(hf.getLocalSymbolMap().getSymbols())
			.map(HighSymbol::getName)
			.filter(name::equals)
			.findFirst()
			.isPresent();
	}

	@Override
	public final List<ClangOpToken> getOpTokens() {
		return getTokens(ClangOpToken.class);
	}

	@Override
	public final List<ClangNode> getTokens() {
		return Collections.unmodifiableList(tokens);
	}

	@Override
	public final int getOffset() {
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
		for (ClangNode node : tokens) {
			builder.append(((ClangToken) node).getText());
		}
		return builder.toString();
	}

}
