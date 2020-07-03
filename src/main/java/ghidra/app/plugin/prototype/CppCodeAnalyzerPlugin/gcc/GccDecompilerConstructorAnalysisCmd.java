package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractDecompilerBasedConstructorAnalysisCmd;
import ghidra.program.model.listing.Function;

import cppclassanalyzer.decompiler.DecompilerAPI;

public class GccDecompilerConstructorAnalysisCmd
		extends AbstractDecompilerBasedConstructorAnalysisCmd {

	private static final String NAME = GccDecompilerConstructorAnalysisCmd.class.getSimpleName();

	protected GccDecompilerConstructorAnalysisCmd(DecompilerAPI api) {
		super(NAME, api);
	}

	public GccDecompilerConstructorAnalysisCmd(ClassTypeInfo typeinfo, DecompilerAPI api) {
		super(NAME, api);
		this.type = typeinfo;
	}

	@Override
	protected boolean analyze() throws Exception {
		boolean result = super.analyze();
		if (result) {
			// set the destructor [not-in-charge]
			Function fun = type.getVtable().getFunctionTables()[0][1];
			setFunction(type, fun, true);
			createVirtualDestructors();
		}
		return result;
	}

	private void createVirtualDestructors() throws Exception {
		Vtable vtable = type.getVtable();
		if (!Vtable.isValid(vtable)) {
			return;
		}
		Function[][] functionTables = vtable.getFunctionTables();
		for (int i = 1; i < functionTables.length; i++) {
			for (int j = 0; j < functionTables[i].length && j < 2; j++) {
				functionTables[i][j].setThunkedFunction(functionTables[0][j]);
				functionTables[i][j].setParentNamespace(type.getGhidraClass());
			}
		}
	}

}
