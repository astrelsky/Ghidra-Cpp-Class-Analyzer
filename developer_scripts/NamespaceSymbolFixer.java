//@category CppClassAnalyzer
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;

import com.google.common.collect.ImmutableList;

public class NamespaceSymbolFixer extends GhidraScript {

	@Override
	public void run() throws Exception {
		fixCategories();
		fixDataTypes();
		fixSymbols();
	}

	private void fixDataTypes() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		Spliterator<DataType> split = Spliterators.spliteratorUnknownSize(
			dtm.getAllDataTypes(), Spliterator.NONNULL | Spliterator.ORDERED);
		List<DataType> types = StreamSupport.stream(split, false)
			.filter(dt -> dt.getName().contains("--"))
			.collect(Collectors.toList());
		println(String.format("Located %d datatypes", types.size()));
		monitor.setMessage("Repairing DataTypes");
		monitor.initialize(types.size());
		for (DataType dt : types) {
			monitor.checkCanceled();
			String name = dt.getName();
			dt.setName(name.replaceAll("--", "::"));
			monitor.incrementProgress(1);
		}
	}

	private void fixCategories() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<DataType> types = ImmutableList.copyOf(dtm.getAllDataTypes());
		monitor.setMessage("Repairing Categories");
		monitor.initialize(types.size());
		for (DataType dt : types) {
			monitor.checkCanceled();
			fixCategory(dt);
			monitor.incrementProgress(1);
		}
	}

	private void fixCategory(DataType dt) throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		Category cat = dtm.getCategory(dt.getCategoryPath());
		String name = cat.getName();
		if (name.contains("--")) {
			cat.setName(name.replaceAll("--", "::"));
		}
	}

	private void fixSymbols() throws Exception {
		SymbolTable table = currentProgram.getSymbolTable();
		List<Symbol> symbols =
			StreamSupport.stream(table.getAllSymbols(false).spliterator(), false)
				.filter(s -> s.getName(true).contains("--"))
				.collect(Collectors.toList());
		monitor.setMessage("Repairing Namespaces");
		monitor.initialize(symbols.size());
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			fixSymbol(symbol);
			monitor.incrementProgress(1);
		}
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			fixNamespace(symbol);
			monitor.incrementProgress(1);
		}
	}

	private void fixSymbol(Symbol symbol) throws Exception {
		Symbol currentSymbol = symbol;
		while (currentSymbol != null && !currentSymbol.isGlobal()) {
			monitor.checkCanceled();
			if (!currentSymbol.checkIsValid()) {
				break;
			}
			String name = currentSymbol.getName();
			if (name.contains("--")) {
				currentSymbol.setName(name.replaceAll("--", "::"), SourceType.USER_DEFINED);
			}
			//fixNamespace(currentSymbol);
			currentSymbol = currentSymbol.getParentSymbol();
		}
	}

	private void fixNamespace(Symbol symbol) throws Exception {
		if (!symbol.checkIsValid()) {
			return;
		}
		Namespace ns = symbol.getParentNamespace();
		if (!ns.isGlobal()) {
			String name = ns.getSymbol().getName();
			if (name.contains("--")) {
				try {
					ns.getSymbol().setName(name.replaceAll("--", "::"), SourceType.USER_DEFINED);
				} catch (DuplicateNameException e) {
					correctNamespace(ns);
				}
				ns.getSymbol().delete();
			}
		} else {
			try {
				String name = symbol.getName();
				symbol.setName(name.replaceAll("--", "::"), SourceType.USER_DEFINED);
			} catch (DuplicateNameException e) {
			}
		}
	}

	private void correctNamespace(Namespace ns) throws Exception {
		String name = ns.getSymbol().getName().replaceAll("--", "::");
		SymbolTable table = currentProgram.getSymbolTable();
		List<Symbol> symbols =
			StreamSupport.stream(table.getChildren(ns.getSymbol()).spliterator(), false)
				.collect(Collectors.toList());
		Namespace newNamespace = table.getNamespace(name, ns.getParentNamespace());
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			symbol.setNamespace(newNamespace);
		}
	}
}