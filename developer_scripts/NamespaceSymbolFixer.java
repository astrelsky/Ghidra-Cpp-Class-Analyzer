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
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;

import com.google.common.collect.ImmutableList;

import util.CollectionUtils;

public class NamespaceSymbolFixer extends GhidraScript {

	@Override
	public void run() throws Exception {
		fixCategories();
		fixDataTypes();
		fixStructures();
		fixSymbols();
		fixClasses();
	}

	private void fixDataTypes() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<DataType> types = CollectionUtils.asStream(dtm.getAllDataTypes())
			.filter(dt -> dt.getName().contains("--"))
			.collect(Collectors.toList());
		println(String.format("Located %d datatypes", types.size()));
		monitor.setMessage("Repairing DataTypes");
		monitor.initialize(types.size());
		for (DataType dt : types) {
			monitor.checkCancelled();
			String name = dt.getName();
			try {
				dt.setName(name.replaceAll("--", "::"));
			} catch (DuplicateNameException e) {
				DataTypePath path =
					new DataTypePath(dt.getCategoryPath(), name.replaceAll("--", "::"));
				printerr("Duplicate type "+path.toString());
			}
			monitor.incrementProgress(1);
		}
	}

	private void fixStructures() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<Structure> structs = CollectionUtils.asList(dtm.getAllStructures());
		monitor.setMessage("Repairing Structure Members");
		for (Structure struct : structs) {
			monitor.checkCancelled();
			if (!struct.getName().equals("vtable")) {
				for (DataTypeComponent comp : struct.getComponents()) {
					String name = comp.getFieldName();
					if (name != null && name.contains("--")) {
						comp.setFieldName(name.replaceAll("--", "::"));
					}
				}
			}
			monitor.incrementProgress(1);
		}
	}

	private void fixCategories() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<DataType> types = ImmutableList.copyOf(dtm.getAllDataTypes());
		monitor.setMessage("Repairing Categories");
		monitor.initialize(types.size());
		for (DataType dt : types) {
			monitor.checkCancelled();
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
		monitor.setMessage("Repairing Symbols");
		monitor.initialize(table.getNumSymbols());
		for (Symbol symbol : table.getAllSymbols(false)) {
			monitor.checkCancelled();
			String name = symbol.getName();
			if (name.contains("--")) {
				symbol.setName(name.replaceAll("--", "::"), SourceType.USER_DEFINED);
			}
			monitor.incrementProgress(1);
		}
	}

	private void fixClasses() throws Exception {
		SymbolTable table = currentProgram.getSymbolTable();
		List<GhidraClass> classes = CollectionUtils.asList(table.getClassNamespaces());
		monitor.setMessage("Repairing Classes");
		monitor.initialize(classes.size());
		for (GhidraClass gc : classes) {
			monitor.checkCancelled();
			String name = gc.getName();
			if (name.contains("--")) {
				gc.getSymbol().setName(name.replaceAll("--", "::"), SourceType.USER_DEFINED);
			}
			monitor.incrementProgress(1);
		}
	}
}
