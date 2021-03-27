package cppclassanalyzer.scanner;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DynlibRttiScanner extends ItaniumAbiRttiScanner {

	public DynlibRttiScanner(Program program) {
		super(program);
	}

	@Override
	protected Set<Address> getReferences(String typeString) throws Exception {
		Program program = manager.getProgram();
		SymbolTable table = program.getSymbolTable();
		Namespace global = program.getGlobalNamespace();
		List<Symbol> symbols = table.getSymbols("_"+VtableModel.MANGLED_PREFIX+typeString, global);
		if (symbols.size() != 1) {
			return Collections.emptySet();
		}
		return GnuUtils.getDirectDataReferences(
			program, symbols.get(0).getAddress(), getDummyMonitor());
	}

	@Override
	public boolean scan(MessageLog log, TaskMonitor monitor) throws CancelledException {
		this.log = log;
		this.monitor = monitor;
		for (String typeString : CLASS_TYPESTRINGS) {
			try {
				if (!getReferences(typeString).isEmpty()) {
					return doScan(log, monitor);
				}
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				log.appendException(e);
				return false;
			}
		}
		return false;
	}
}
