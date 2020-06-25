package cppclassanalyzer.decompiler.action;

import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.AbstractNonPackageDecompilerAction;
import ghidra.app.plugin.prototype.ClassTypeInfoManagerPlugin;

import cppclassanalyzer.cmd.FillOutClassCmd;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;

public class FillOutClassAction extends AbstractNonPackageDecompilerAction {

	private static final String NAME = FillOutClassAction.class.getSimpleName();
	private final ClassTypeInfoManagerPlugin plugin;

	public FillOutClassAction(ClassTypeInfoManagerPlugin plugin) {
		super(NAME);
		this.plugin = plugin;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!context.hasRealFunction()) {
			return false;
		}
		ProgramClassTypeInfoManager manager = plugin.getManager(context.getProgram());
		if (manager == null) {
			return false;
		}
		return manager.getType(context.getFunction()) != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		FillOutClassCmd cmd = new FillOutClassCmd(context);
		context.getTool().executeBackgroundCommand(cmd, context.getProgram());
	}

}
