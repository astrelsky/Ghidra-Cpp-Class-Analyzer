package ghidra.app.plugin.prototype;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;

public interface TypeInfoManagerListener {
	void managerOpened(ClassTypeInfoManager manager);
	void managerClosed(ClassTypeInfoManager manager);
	void typeAdded(ClassTypeInfoDB type);
	void typeRemoved(ClassTypeInfoDB type);
	void typeUpdated(ClassTypeInfoDB type);
}