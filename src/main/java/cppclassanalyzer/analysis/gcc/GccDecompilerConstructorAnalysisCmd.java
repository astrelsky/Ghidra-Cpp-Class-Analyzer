package cppclassanalyzer.analysis.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.model.listing.Function;

import cppclassanalyzer.analysis.cmd.AbstractDecompilerBasedConstructorAnalysisCmd;
import cppclassanalyzer.decompiler.DecompilerAPI;

public class GccDecompilerConstructorAnalysisCmd
		extends AbstractDecompilerBasedConstructorAnalysisCmd {

	private static final String NAME = GccDecompilerConstructorAnalysisCmd.class.getSimpleName();

	GccDecompilerConstructorAnalysisCmd(DecompilerAPI api) {
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
		for (int i = 0; i < functionTables.length; i++) {
			for (int j = 0; j < functionTables[i].length && j < 2; j++) {
				if (i == 0) {
					if (functionTables[i][j] == null) {
						continue;
					}
					setFunction(type, functionTables[i][j], true);
				} else {
					functionTables[i][j].setThunkedFunction(functionTables[0][j]);
					functionTables[i][j].setParentNamespace(type.getGhidraClass());
				}
			}
		}
	}

}
