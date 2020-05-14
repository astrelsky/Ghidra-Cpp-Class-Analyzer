package ghidra.app.plugin.prototype;

import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;

public interface TypeInfoManagerListener {
	void managerOpened(ClassTypeInfoManager manager);
	void managerClosed(ClassTypeInfoManager manager);
	void typeAdded(ClassTypeInfoDB type);
	void typeRemoved(ClassTypeInfoDB type);
	void typeUpdated(ClassTypeInfoDB type);
}