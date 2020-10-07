package cppclassanalyzer.provider;

import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.ItaniumAbiClassTypeInfoManager;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.service.RttiManagerProvider;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public final class ItaniumAbiRttiManagerProvider implements RttiManagerProvider {

	@Override
	public boolean canProvideManager(Program program) {
		return GnuUtils.isGnuCompiler(program);
	}

	@Override
	public ProgramClassTypeInfoManager getManager(Program program) {
		if (!canProvideManager(program)) {
			return null;
		}
		PluginTool tool = CppClassAnalyzerUtils.getTool(program);
		ClassTypeInfoManagerService service = tool.getService(ClassTypeInfoManagerService.class);
		if (service instanceof ClassTypeInfoManagerPlugin) {
			return new ItaniumAbiClassTypeInfoManager(
				(ClassTypeInfoManagerPlugin) service, (ProgramDB) program);
		}
		return null;
	}

}
