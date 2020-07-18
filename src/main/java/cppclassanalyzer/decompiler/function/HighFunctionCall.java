package cppclassanalyzer.decompiler.function;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;

public final class HighFunctionCall implements Comparable<HighFunctionCall> {

	private final HighFunction hf;
	private final ClangFuncNameToken name;
	private final List<HighFunctionCallParameter> parameters;

	private HighFunctionCall(ClangStatement statement, FunctionNameParamSupplier supplier) {
		this.hf = statement.getClangFunction().getHighFunction();
		this.name = supplier.getFunctionName();
		this.parameters = supplier.getParameterGroups()
			.stream()
			.map(HighFunctionCallParameter::new)
			.collect(Collectors.toList());
	}

	public static HighFunctionCall getHighFunctionCall(ClangStatement statement) {
		FunctionNameParamSupplier supplier = new FunctionNameParamSupplier(statement);
		if (supplier.getFunctionName() == null) {
			return null;
		}
		return new HighFunctionCall(statement, supplier);
	}

	private VarnodeAST getVarnode() {
		return (VarnodeAST) name.getPcodeOp().getInput(0);
	}

	public Function getFunction() {
		VarnodeAST varnode = getVarnode();
		long offset = varnode.getOffset();
		AddressSpace space = hf.getAddressFactory().getAddressSpace(varnode.getSpace());
		Listing listing = getProgram().getListing();
		Function f = listing.getFunctionAt(space.getAddress(offset));
		return f != null ? f : getExternalFunction(space.getAddress(offset));
	}

	private Function getExternalFunction(Address address) {
		Program program = getProgram();
		Listing listing = getProgram().getListing();
		Data data = listing.getDataAt(address);
		if (data != null && data.isPointer()) {
			ExternalManager man = program.getExternalManager();
			ExternalLocationIterator it = man.getExternalLocations((Address) data.getValue());
			if (it.hasNext()) {
				return it.next().getFunction();
			}
		}
		return null;
	}

	private Program getProgram() {
		return hf.getFunction().getProgram();
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
