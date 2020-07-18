package cppclassanalyzer.decompiler.function;

import java.util.List;

import ghidra.app.decompiler.*;

public interface HighStructAccess {

	public boolean hasFieldToken();

	public ClangFieldToken getFieldToken();

	public ClangVariableToken getVariableToken();

	public boolean hasLocalRef();

	public int getOffset();

	public List<ClangOpToken> getOpTokens();

	public List<ClangNode> getTokens();

	public AccessType getAccessType();

	public static enum AccessType {
		PARAMETER,
		GLOBAL
	}
}
