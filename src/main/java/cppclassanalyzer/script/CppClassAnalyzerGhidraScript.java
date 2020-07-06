package cppclassanalyzer.script;

import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;

/**
 * A GhidraScript extension providing convenient access to the current
 * {@link ProgramClassTypeInfoManager}.
 */
public abstract class CppClassAnalyzerGhidraScript extends GhidraScript {

	protected ProgramClassTypeInfoManager currentManager;

	@Override
	protected void loadPropertiesFile() throws IOException {
		super.loadPropertiesFile();
		ClassTypeInfoManagerService service =
			state.getTool().getService(ClassTypeInfoManagerService.class);
		this.currentManager = service.getManager(currentProgram);
	}

	/**
	 * A convience method for demangling the provided label
	 * @param mangled the mangled label
	 * @return the demangled object or null if it was not mangled
	 */
	protected final DemangledObject demangle(String mangled) {
		return DemanglerUtil.demangle(currentProgram, mangled);
	}
}
