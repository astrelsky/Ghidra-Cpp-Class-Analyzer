package cppclassanalyzer.service;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;

/**
 * Provides a {@link ProgramClassTypeInfoManager}.
 * <p>
 * An RttiManagerProvider <b>may not</b> fail in Headless mode
 */
public interface RttiManagerProvider extends ExtensionPoint {

	public boolean canProvideManager(Program program);

	public ProgramClassTypeInfoManager getManager(Program program);
}
