package cppclassanalyzer.utils;

import java.util.Arrays;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public final class CppClassAnalyzerUtils {

    private CppClassAnalyzerUtils() {
    }

    /**
     * Gets the first PluginTool which has the provided program opened
     * @param program the opened program
     * @return the first found PluginTool or null if none found
     */
    public static PluginTool getTool(Program program) {
        Project project = AppInfo.getActiveProject();
		PluginTool[] tools = project.getToolManager().getRunningTools();
		return Arrays.stream(tools)
            .filter(program::isUsedBy)
            .findFirst()
            .orElse(null);
    }
}