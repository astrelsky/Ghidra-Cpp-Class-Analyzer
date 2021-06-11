package cppclassanalyzer.script;

import java.io.IOException;

import ghidra.app.util.headless.HeadlessScript;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.plugin.HeadlessClassTypeInfoManagerService;
import cppclassanalyzer.service.ClassTypeInfoManagerService;

public abstract class CppClassAnalyzerHeadlessScript extends HeadlessScript {

	protected ProgramClassTypeInfoManager currentManager;

	@Override
	protected void loadPropertiesFile() throws IOException {
		super.loadPropertiesFile();
		this.currentManager = getService().getManager(currentProgram);
	}

	/**
	 * Gets the ClassTypeInfoManagerService
	 * @return the ClassTypeInfoManagerService
	 */
	protected final ClassTypeInfoManagerService getService() {
		return HeadlessClassTypeInfoManagerService.getInstance();
	}
}
