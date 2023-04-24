package cppclassanalyzer.cmd;

import java.util.Objects;

import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.vtable.ArchivedVtable;

/**
 * BackgroundCommand to apply virtual function definitions to the functions
 * pointed to in the provided vtable.
 */
public class ApplyVtableDefinitionsBackgroundCmd extends BackgroundCommand {

	private final Vtable vtable;
	private final ArchivedVtable archived;

	/**
	 * Constructs a new ApplyVtableDefinitionsBackgroundCmd
	 * @param vtable the vtable to apply the definitions to
	 * @param archived the archived vtable
	 */
	public ApplyVtableDefinitionsBackgroundCmd(Vtable vtable, ArchivedVtable archived) {
		this.vtable = Objects.requireNonNull(vtable);
		this.archived = Objects.requireNonNull(archived);
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if (!(obj instanceof Program)) {
			setStatusMsg("Can only be applied to a program");
			return false;
		}
		Function[][] functions = vtable.getFunctionTables();
		FunctionDefinition[][] definitions = archived.getFunctionDefinitions();
		if (functions.length != definitions.length) {
			return reportNonMatchingData();
		}
		for (int i = 0; i < functions.length; i++) {
			if (functions[i].length != definitions[i].length) {
				return reportNonMatchingData();
			}
		}
		try {
			for (int i = 0; i < functions.length; i++) {
				monitor.checkCancelled();
				for (int j = 0; j < functions[i].length; j++) {
					monitor.checkCancelled();
					Function function = functions[i][j];
					FunctionDefinition definition = definitions[i][j];
					if (function == null || definition == null) {
						// nothing to do
						continue;
					}
					ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
						function.getEntryPoint(), definition, SourceType.ANALYSIS, false, true);
					if (!cmd.applyTo(function.getProgram(), monitor)) {
						return false;
					}
					if (function.isGlobal()) {
						function.setParentNamespace(vtable.getTypeInfo().getGhidraClass());
					}
				}
			}
		} catch (CancelledException e) {
			setStatusMsg("Task Cancelled");
			return false;
		} catch (Exception e) {
			setStatusMsg(e.getLocalizedMessage());
			return false;
		}
		return true;
	}

	private boolean reportNonMatchingData() {
		setStatusMsg("Vtable definitions for " + vtable.getTypeInfo().getFullName()
			+ " doesn't match archived data");
		return false;
	}

}
