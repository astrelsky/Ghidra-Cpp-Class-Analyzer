package cppclassanalyzer.data.vtable;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.model.data.FunctionDefinition;

import cppclassanalyzer.data.ArchivedRttiData;

public interface ArchivedVtable extends ArchivedRttiData {
	
	/**
	 * Returns the TypeInfo Model this vtable points to
	 * @return the pointed to TypeInfo Model
	 */
	public ClassTypeInfo getTypeInfo();
	
	public FunctionDefinition[][] getFunctionDefinitions();
}