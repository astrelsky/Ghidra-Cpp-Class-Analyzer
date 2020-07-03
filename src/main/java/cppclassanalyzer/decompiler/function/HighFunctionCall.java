package cppclassanalyzer.decompiler.function;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.*;

public final class HighFunctionCall implements Comparable<HighFunctionCall> {

	private final HighFunction hf;
	private final ClangFuncNameToken name;
	private final List<HighFunctionCallParameter> parameters;

	public HighFunctionCall(ClangStatement statement) {
		FunctionNameParamSupplier supplier = new FunctionNameParamSupplier(statement);
		if (supplier.getFunctionName() == null) {
			throw new IllegalArgumentException("statement is not a valid HighFunctionCall");
		}
		this.hf = statement.getClangFunction().getHighFunction();
		this.name = supplier.getFunctionName();
		this.parameters = supplier.getParameterGroups()
			.stream()
			.map(group -> new HighFunctionCallParameter(hf, group))
			.collect(Collectors.toList());
	}

	private VarnodeAST getVarnode() {
		return (VarnodeAST) name.getPcodeOp().getInput(0);
	}

	public Function getFunction() {
		VarnodeAST varnode = getVarnode();
		long offset = varnode.getOffset();
		AddressSpace space = hf.getAddressFactory().getAddressSpace(varnode.getSpace());
		Listing listing = hf.getFunction().getProgram().getListing();
		return listing.getFunctionAt(space.getAddress(offset));
	}

	public Address getAddress() {
		return getVarnode().getPCAddress();
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(name.getText());
		builder.append('(');
		Iterator<HighFunctionCallParameter> params = parameters.iterator();
		while (params.hasNext()) {
			HighFunctionCallParameter param = params.next();
			builder.append(param.toString());
			if (params.hasNext()) {
				builder.append(", ");
			}
		}
		builder.append(");");
		return builder.toString();
	}

	public List<HighFunctionCallParameter> getParameters() {
		return parameters;
	}

	private static boolean isSeparator(ClangToken token) {
		if (token instanceof ClangOpToken) {
			return token.getText().equals(",");
		}
		return false;
	}

	private static final class FunctionNameParamSupplier {

		private final ClangStatement statement;
		private int nameIndex;

		FunctionNameParamSupplier(ClangStatement statement) {
			this.statement = statement;
			this.nameIndex = -1;
		}

		ClangFuncNameToken getFunctionName() {
			if (nameIndex == -1) {
				for (int i = 0; i < statement.numChildren(); i++) {
					if (statement.Child(i) instanceof ClangFuncNameToken) {
						nameIndex = i;
						break;
					}
				}
			}
			return nameIndex != -1 ? (ClangFuncNameToken) statement.Child(nameIndex) : null;
		}

		List<ClangTokenGroup> getParameterGroups() {
			List<ClangToken> tokens = IntStream.range(nameIndex + 1, statement.numChildren())
				.mapToObj(statement::Child)
				.filter(ClangToken.class::isInstance)
				.map(ClangToken.class::cast)
				.collect(Collectors.toList());
			List<ClangTokenGroup> tokenLists = new ArrayList<>();
			int prev = 0;
			for (int i = 0; i < tokens.size(); i++) {
				if (isSeparator(tokens.get(i))) {
					ClangTokenGroup group = new ClangTokenGroup(null);
					List<ClangToken> groupTokens;
					if (prev == 0) {
						groupTokens = tokens.subList(prev+1, i++);
					} else {
						groupTokens = tokens.subList(prev, i++);
					}
					prev = i;
					groupTokens.forEach(group::AddTokenGroup);
					tokenLists.add(group);
				}
			}
			if (prev != tokens.size()) {
				ClangTokenGroup group = new ClangTokenGroup(null);
				List<ClangToken> groupTokens = tokens.subList(prev, tokens.size()-1);
				groupTokens.forEach(group::AddTokenGroup);
				tokenLists.add(group);
			}
			return tokenLists;
		}
	}

	@Override
	public int compareTo(HighFunctionCall o) {
		return name.getMinAddress().compareTo(o.name.getMinAddress());
	}

}
