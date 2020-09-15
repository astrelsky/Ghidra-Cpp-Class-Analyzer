package cppclassanalyzer.script;

import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.service.ClassTypeInfoManagerService;

/**
 * A GhidraScript extension providing convenient access to the current
 * {@link ProgramClassTypeInfoManager}.
 */
public abstract class CppClassAnalyzerGhidraScript extends GhidraScript {

	protected ProgramClassTypeInfoManager currentManager;

	@Override
	protected void loadPropertiesFile() throws IOException {
		super.loadPropertiesFile();
		this.currentManager = getService().getManager(currentProgram);
	}

	/**
	 * A convience method for demangling the provided label
	 * @param mangled the mangled label
	 * @return the demangled object or null if it was not mangled
	 */
	protected final DemangledObject demangle(String mangled) {
		return DemanglerUtil.demangle(currentProgram, mangled);
	}

	/**
	 * Gets the ClassTypeInfoManagerService
	 * @return the ClassTypeInfoManagerService
	 */
	protected final ClassTypeInfoManagerService getService() {
		return state.getTool().getService(ClassTypeInfoManagerService.class);
	}
}
