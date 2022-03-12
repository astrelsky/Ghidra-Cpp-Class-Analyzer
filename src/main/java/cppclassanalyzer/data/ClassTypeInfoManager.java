package cppclassanalyzer.data;

import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.framework.model.DomainObjectListener;

import cppclassanalyzer.plugin.typemgr.node.TypeInfoTreeNodeManager;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import db.util.ErrorHandler;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Disposable;

/**
 * ClassTypeInfoManager manages all {@link ClassTypeInfo} within
 * a {@link ghidra.framework.model.DomainObject DomainObject}
 */
public interface ClassTypeInfoManager extends Disposable, ErrorHandler {

	/** The value which represents an invalid database key */
	public static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	/**
	 * Gets the name of this manager
	 * @return the managers name
	 */
	String getName();

	/**
	 * Gets the icon for this manager to be used in the
	 * {@link cppclassanalyzer.plugin.typemgr.TypeInfoArchiveGTree TypeInfoArchiveGTree}
	 * @param expanded true if the manager tree node is expanded
	 * @return the icon to be used in the tree
	 */
	Icon getIcon(boolean expanded);

	/**
	 * Returns a ClassTypeInfo that is managed by this ClassTypeInfoManager.
	 * If one does not currently exist a new one is created.
	 * @param type the type to resolve
	 * @return the equivalent type managed by this ClassTypeInfoManager
	 */
	ClassTypeInfoDB resolve(ClassTypeInfo type);

	/**
	 * Gets the ClassTypeInfo for the corresponding database key
	 * @param key the database key
	 * @return the ClassTypeInfo or null if it doesn't exist
	 */
	ClassTypeInfoDB getType(long key);

	/**
	 * Gets the ClassTypeInfo for the corresponding {@link GhidraClass}
	 * @param gc the GhidraClass
	 * @return the ClassTypeInfo or null if it doesn't exist
	 * @throws UnresolvedClassTypeInfoException if this type requires a copy relocation
	 * which cannot be resolved.
	 */
	ClassTypeInfoDB getType(GhidraClass gc) throws UnresolvedClassTypeInfoException;

	/**
	 * Gets the ClassTypeInfo for the corresponding {@link Function}
	 * @param fun the function
	 * @return the ClassTypeInfo or null if it doesn't exist
	 * @throws UnresolvedClassTypeInfoException if this type requires a copy relocation
	 * which cannot be resolved.
	 */
	ClassTypeInfoDB getType(Function fun) throws UnresolvedClassTypeInfoException;

	/**
	 * Gets the ClassTypeInfo with the specified name and {@link Namespace}
	 * @param name the type's name
	 * @param namespace the type's namespace
	 * @return the ClassTypeInfo or null if it doesn't exist
	 * @throws UnresolvedClassTypeInfoException if this type requires a copy relocation
	 * which cannot be resolved.
	 */
	ClassTypeInfoDB getType(String name, Namespace namespace)
		throws UnresolvedClassTypeInfoException;

	/**
	 * Gets the ClassTypeInfo with the specified symbol.
	 * The supplied symbol should be mangled.
	 * @param symbolName the mangled symbol name
	 * @return the ClassTypeInfo or null if it doesn't exist
	 * @throws UnresolvedClassTypeInfoException if this type requires a copy relocation
	 * which cannot be resolved.
	 */
	ClassTypeInfoDB getType(String symbolName) throws UnresolvedClassTypeInfoException;

	/**
	 * Gets an iterable over all the managed ClassTypeInfos
	 * @return an iterable over all the managed ClassTypeInfos
	 */
	Iterable<ClassTypeInfoDB> getTypes();

	/**
	 * Gets a stream of all the managed ClassTypeInfos
	 * @return a stream of all the managed ClassTypeInfos
	 */
	Stream<ClassTypeInfoDB> getTypeStream();

	/**
	 * Gets the number of managed ClassTypeInfos
	 * @return the number of managed ClassTypeInfos
	 */
	int getTypeCount();

	/**
	 * Gets the {@link TypeInfoTreeNodeManager} for this ClassTypeInfoManager
	 * @return this manager's TypeInfoTreeNodeManager
	 */
	TypeInfoTreeNodeManager getTreeNodeManager();

	default void addListener(DomainObjectListener listener) {
	}

	default void removeListener(DomainObjectListener listener) {
	}
}
