package cppclassanalyzer.provider;

import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.VsClassTypeInfoManager;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.service.RttiManagerProvider;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public final class VsRttiManagerProvider implements RttiManagerProvider {

	@Override
	public boolean canProvideManager(Program program) {
		return PEUtil.canAnalyze(program) && !GnuUtils.isGnuCompiler(program);
	}

	@Override
	public ProgramClassTypeInfoManager getManager(Program program) {
		if (!canProvideManager(program)) {
			return null;
		}
		PluginTool tool = CppClassAnalyzerUtils.getTool(program);
		ClassTypeInfoManagerService service = tool.getService(ClassTypeInfoManagerService.class);
		if (service instanceof ClassTypeInfoManagerPlugin) {
			return new VsClassTypeInfoManager(
				(ClassTypeInfoManagerPlugin) service, (ProgramDB) program);
		}
		return null;
	}
}
