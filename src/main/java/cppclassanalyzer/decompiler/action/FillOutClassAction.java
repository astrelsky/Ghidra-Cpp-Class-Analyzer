package cppclassanalyzer.decompiler.action;

import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.AbstractNonPackageDecompilerAction;

import cppclassanalyzer.cmd.FillOutClassBackgroundCmd;
import cppclassanalyzer.data.manager.ClassTypeInfoManagerDB;
import cppclassanalyzer.plugin.ClassTypeInfoManagerPlugin;
import docking.action.MenuData;

public class FillOutClassAction extends AbstractNonPackageDecompilerAction {

	private static final String NAME = FillOutClassAction.class.getSimpleName();
	private static final MenuData MENU_ENTRY =
		new MenuData(new String[] { "Fill Out Class" }, "Decompile");

	private final ClassTypeInfoManagerPlugin plugin;

	public FillOutClassAction(ClassTypeInfoManagerPlugin plugin) {
		super(NAME);
		this.plugin = plugin;
		setPopupMenuData(MENU_ENTRY);
		setDescription("Automatically fill out class members");
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!context.hasRealFunction()) {
			return false;
		}
		ClassTypeInfoManagerDB manager =
			(ClassTypeInfoManagerDB) plugin.getManager(context.getProgram());
		if (manager == null) {
			return false;
		}
		try {
			return manager.getType(context.getFunction()) != null;
		} catch (UnresolvedClassTypeInfoException e) {
			// allowing the use of the action will just cause the exception to be thrown again
			return false;
		}
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		FillOutClassBackgroundCmd cmd = new FillOutClassBackgroundCmd(context);
		context.getTool().executeBackgroundCommand(cmd, context.getProgram());
	}

}
