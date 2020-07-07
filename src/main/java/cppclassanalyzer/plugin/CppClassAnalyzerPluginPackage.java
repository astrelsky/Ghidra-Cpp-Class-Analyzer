package cppclassanalyzer.plugin;

import ghidra.framework.plugintool.util.PluginPackage;

import resources.ResourceManager;

/**
 * The {@link PluginPackage} for the {@value #NAME}
 */
public class CppClassAnalyzerPluginPackage extends PluginPackage {

	public static final String NAME = "Ghidra C++ Class Analyzer";
	private static final String DESCRIPTION = "These plugins are for analyzing C++ Classes.";

	public CppClassAnalyzerPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/cpp_logo.png"), DESCRIPTION);
	}

}
