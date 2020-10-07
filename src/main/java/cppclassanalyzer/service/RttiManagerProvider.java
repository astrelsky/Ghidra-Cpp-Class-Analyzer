package cppclassanalyzer.service;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;

public interface RttiManagerProvider extends ExtensionPoint {

	public boolean canProvideManager(Program program);

	public ProgramClassTypeInfoManager getManager(Program program);
}
