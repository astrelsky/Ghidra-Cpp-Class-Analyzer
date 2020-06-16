package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.gcc;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.AbstractDecompilerBasedConstructorAnalysisCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.AssertException;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

public class GccDecompilerConstructorAnalysisCmd
		extends AbstractDecompilerBasedConstructorAnalysisCmd {

	private static final String NAME = GccDecompilerConstructorAnalysisCmd.class.getSimpleName();

	GccDecompilerConstructorAnalysisCmd(int timeout) {
		super(NAME, timeout);
	}

	public GccDecompilerConstructorAnalysisCmd(ClassTypeInfo typeinfo, int timeout) {
		super(NAME, timeout);
		this.type = typeinfo;
	}

	@Override
	protected List<ClassFunction> getFunctions() {
		Vtable vtable = type.getVtable();
		if (!Vtable.isValid(vtable)) {
			return Collections.emptyList();
		}
		Address[] tableAddresses = vtable.getTableAddresses();
		if (tableAddresses.length == 0) {
			// no virtual functions, nothing to analyze.
			return Collections.emptyList();
		}
		Data data = listing.getDataContaining(tableAddresses[0]);
		if (data == null) {
			String msg = String.format(
				"Vtable data for %s at %s has been deleted",
				type.getFullName(),
				tableAddresses[0]);
			throw new AssertException(msg);
		}
		return CollectionUtils.asStream(data.getReferenceIteratorTo())
			.filter(r -> r.getReferenceType().isData())
			.map(Reference::getFromAddress)
			.map(listing::getFunctionContaining)
			.filter(Objects::nonNull)
			.filter(CppClassAnalyzerUtils::isDefaultFunction)
			.map(f -> new ClassFunction(f, vtable.containsFunction(f)))
			.collect(Collectors.toList());
	}

	@Override
	protected boolean analyze() throws Exception {
		boolean result = super.analyze();
		if (result) {
			// set the destructor [not-in-charge]
			Vtable vtable = type.getVtable();
			if (!Vtable.isValid(vtable)) {
				return result;
			}
			Function fun = vtable.getFunctionTables()[0][1];
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