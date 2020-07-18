package cppclassanalyzer.decompiler.function;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.*;

public final class HighVariableAssignment extends AbstractHighStructAccess {

	public HighVariableAssignment(ClangStatement statement) {
		super(statement);
	}

	private Stream<VariableStorage> getVarnodeStream() {
		return getTokens()
			.stream()
			.filter(ClangVariableToken.class::isInstance)
			.map(ClangVariableToken.class::cast)
			.map(ClangVariableToken::getPcodeOp)
			.map(PcodeOp::getInputs)
			.flatMap(Arrays::stream)
			.map(Varnode::getHigh)
			.filter(Objects::nonNull)
			.map(HighVariable::getSymbol)
			.filter(Objects::nonNull)
			.map(HighSymbol::getStorage)
			.filter(HighVariableAssignment::isAddress);
	}

	private static boolean isAddress(VariableStorage storage) {
		return storage.isMemoryStorage()
			&& !(storage.isRegisterStorage() || storage.isStackStorage());
	}

	public boolean hasGlobalRef() {
		return getVarnodeStream()
			.findAny()
			.isPresent();
	}

	public Address getGlobalRefAddress() {
		return getVarnodeStream()
			.map(VariableStorage::getMinAddress)
			.findFirst()
			.orElse(null);
	}

	@Override
	public AccessType getAccessType() {
		return AccessType.GLOBAL;
	}
}
