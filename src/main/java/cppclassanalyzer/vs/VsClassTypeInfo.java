package cppclassanalyzer.vs;

import java.util.Map;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import util.CollectionUtils;

public interface VsClassTypeInfo extends ClassTypeInfo {

	public static final String PURE_VIRTUAL_FUNCTION_NAME = "_purecall";
	public static final String LOCATOR_SYMBOL_NAME = Rtti4Model.DATA_TYPE_NAME;
	public static final String HIERARCHY_SYMBOL_NAME = Rtti3Model.DATA_TYPE_NAME;
	public static final String BASE_ARRAY_SYMBOL_NAME = Rtti2Model.DATA_TYPE_NAME;
	public static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

	public Map<ClassTypeInfo, Integer> getBaseOffsets();
	public Rtti1Model getBaseModel();
	default Rtti2Model getBaseClassArray() {
		try {
			return getHierarchyDescriptor().getRtti2Model();
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}
	public Rtti3Model getHierarchyDescriptor();
	public TypeDescriptorModel getTypeDescriptor();

	default public Rtti4Model getCompleteObjectLocator() {
		GhidraClass gc = getGhidraClass();
		Program program = gc.getSymbol().getProgram();
		SymbolIterator it = program.getSymbolTable().getChildren(gc.getSymbol());
		for (Symbol symbol : CollectionUtils.asIterable(it)) {
			if (symbol.getName().contains(LOCATOR_SYMBOL_NAME)) {
				Rtti4Model locatorModel = new Rtti4Model(
					program, symbol.getAddress(), DEFAULT_OPTIONS);
				try {
					locatorModel.validate();
					return locatorModel;
				} catch (InvalidDataTypeException e) {
					// continue searching
				}
			}
		}
		return null;
	}

	static Rtti4Model findRtti4Model(Program program, Address address, TaskMonitor monitor)
			throws CancelledException {
		return RttiModelSearcher.findRtti4Model(program, address, monitor);
	}

	static boolean symbolFilter(Symbol symbol) {
		return symbol.getName().contains(LOCATOR_SYMBOL_NAME);
	}

	@Override
	default public boolean isAbstract() {
		return CppClassAnalyzerUtils.isAbstract(this, PURE_VIRTUAL_FUNCTION_NAME);
	}

}
