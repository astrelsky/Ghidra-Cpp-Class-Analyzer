package cppclassanalyzer.decompiler.function;

import ghidra.app.decompiler.*;

public final class HighFunctionCallParameter extends AbstractHighStructAccess {

	HighFunctionCallParameter(ClangTokenGroup group) {
		super(group);
	}

	@Override
	public AccessType getAccessType() {
		return AccessType.PARAMETER;
	}

}
