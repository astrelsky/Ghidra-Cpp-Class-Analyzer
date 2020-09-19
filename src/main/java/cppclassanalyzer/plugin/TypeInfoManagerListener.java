package cppclassanalyzer.plugin;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;

/**
 * Listener interface for {@link ClassTypeInfoManager}
 */
public interface TypeInfoManagerListener {

	/**
	 * Invoked when a type has been added to a manager
	 * @param type the added type
	 */
	void typeAdded(ClassTypeInfoDB type);

	/**
	 * Invoked when a type has been removed to a manager
	 * @param type the removed type
	 */
	void typeRemoved(ClassTypeInfoDB type);

	/**
	 * Invoked when a type has been updated
	 * @param type the updated type
	 */
	void typeUpdated(ClassTypeInfoDB type);
}
