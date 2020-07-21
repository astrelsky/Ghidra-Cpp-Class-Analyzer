package cppclassanalyzer.vs;

import java.util.Map;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public interface VsClassTypeInfo extends ClassTypeInfo {

	public static final String LOCATOR_SYMBOL_NAME = Rtti4Model.DATA_TYPE_NAME;
	public static final String HIERARCHY_SYMBOL_NAME = Rtti3Model.DATA_TYPE_NAME;
	public static final String BASE_ARRAY_SYMBOL_NAME = Rtti2Model.DATA_TYPE_NAME;
	public static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

	public Map<ClassTypeInfo, Integer> getBaseOffsets();
	public Rtti1Model getBaseModel();
	public Rtti2Model getBaseClassArray();
	public Rtti3Model getHierarchyDescriptor();
	public TypeDescriptorModel getTypeDescriptor();

	@Override
	default public boolean isAbstract() {
		return CppClassAnalyzerUtils.isAbstract(this, VsVtableModel.PURE_VIRTUAL_FUNCTION_NAME);
	}

}
