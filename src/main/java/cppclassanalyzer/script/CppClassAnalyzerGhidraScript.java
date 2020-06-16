package cppclassanalyzer.script;

import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ClassTypeInfoManagerService;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;

import cppclassanalyzer.data.ClassTypeInfoManager;

/**
 * A GhidraScript extension providing convenient access to the current
 * {@link ClassTypeInfoManager}.
 */
public abstract class CppClassAnalyzerGhidraScript extends GhidraScript {

	protected ClassTypeInfoManager currentManager;

	@Override
	protected void loadPropertiesFile() throws IOException {
		super.loadPropertiesFile();
		ClassTypeInfoManagerService service =
			state.getTool().getService(ClassTypeInfoManagerService.class);
		this.currentManager = service.getManager(currentProgram);
	}

	protected final DemangledObject demangle(String mangled) {
		return DemanglerUtil.demangle(currentProgram, mangled);
	}
}