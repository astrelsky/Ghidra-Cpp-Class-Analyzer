package cppclassanalyzer.wrapper;

import java.util.Map;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;

import cppclassanalyzer.utils.CppClassAnalyzerUtils;

public interface VsClassTypeInfo extends ClassTypeInfo {
	public static final String PURE_VIRTUAL_FUNCTION_NAME = "_purecall";

	public Rtti1Model getBaseModel();
	public Map<ClassTypeInfo, Integer> getBaseOffsets();
	public Rtti3Model getHierarchyDescriptor();

	@Override
	default public boolean isAbstract() {
		return CppClassAnalyzerUtils.isAbstract(this, PURE_VIRTUAL_FUNCTION_NAME);
	}

}
