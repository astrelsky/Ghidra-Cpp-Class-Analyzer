package cppclassanalyzer.data;

import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.framework.model.DomainObjectListener;

import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.data.vtable.ArchivedGnuVtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.UniversalID;

/**
 * {@link ClassTypeInfoManager} for a {@link Program}
 */
public interface ProgramClassTypeInfoManager extends TypeInfoManager, ClassTypeInfoManager {

	/**
	 * Gets the program
	 * @return the program
	 */
	Program getProgram();

	/**
	 * Gets the ClassTypeInfo at the specified address
	 * @param address the address of the ClassTypeInfo
	 * @return the ClassTypeInfo or null if invalid
	 * @throws UnresolvedClassTypeInfoException if this type requires a copy relocation
	 * which cannot be resolved.
	 */
	ClassTypeInfoDB getType(Address address) throws UnresolvedClassTypeInfoException;

	/**
	 * Returns a Vtable that is managed by this ProgramClassTypeInfoManager.
	 * If one does not currently exist a new one is created.
	 * @param vtable the vtable to resolve
	 * @return the equivalent vtable managed by this ProgramClassTypeInfoManager
	 */
	Vtable resolve(Vtable vtable);

	/**
	 * Gets the Vtable at the specified address
	 * @param address the address of the vtable
	 * @return the vtable at the address or null if none is present
	 */
	Vtable getVtable(Address address);

	@Override
	default Iterable<ClassTypeInfoDB> getTypes() {
		return getTypes(false);
	}

	/**
	 * Gets an iterable over all the managed ClassTypeInfos in the specified direction
	 * @param reverse true if the types should be provided in reverse
	 * @return an iterable over all the managed ClassTypeInfos
	 */
	Iterable<ClassTypeInfoDB> getTypes(boolean reverse);

	/**
	 * Gets an iterable over all the managed Vtables
	 * @return an iterable over all the managed Vtables
	 */
	default Iterable<Vtable> getVtables() {
		return getVtableIterable(false);
	}

	/**
	 * Gets an iterable over all the managed Vtables in the specified direction
	 * @param reverse true if the Vtables should be provided in reverse
	 * @return an iterable over all the managed Vtables
	 */
	Iterable<Vtable> getVtableIterable(boolean reverse);

	/**
	 * Gets the number of managed Vtables
	 * @return the number of managed Vtables
	 */
	int getVtableCount();

	@Override
	default Stream<ClassTypeInfoDB> getTypeStream() {
		return getTypeStream(false);
	}

	/**
	 * Gets a stream of all the managed ClassTypeInfos in the specified direction
	 * @param reverse true if the types should be provided in reverse
	 * @return a stream of all the managed ClassTypeInfos
	 */
	Stream<ClassTypeInfoDB> getTypeStream(boolean reverse);

	/**
	 * Gets a stream of all the managed Vtables
	 * @return a stream of all the managed Vtables
	 */
	Stream<Vtable> getVtableStream();

	/**
	 * Returns a ClassTypeInfo that is managed by this ClassTypeInfoManager.
	 * If the ArchivedClassTypeInfo hasn't already been resolved the type
	 * will be created and all required data will be added to the program.
	 * @param type the type to resolve
	 * @return the equivalent type managed by this ClassTypeInfoManager
	 */
	ClassTypeInfoDB resolve(ArchivedClassTypeInfo type);

	/**
	 * Returns a Vtable that is managed by this ClassTypeInfoManager.
	 * If the ArchivedGnuVtable hasn't already been resolved the vtable
	 * will be created and all required data will be added to the program.
	 * @param vtable the vtable to resolve
	 * @return the equivalent vtable managed by this ClassTypeInfoManager
	 */
	Vtable resolve(ArchivedGnuVtable vtable);

	/**
	 * Gets the Type info at the specified address. If the TypeInfo is a ClassTypeInfo
	 * it can be resolved if requested.
	 * @param address the address of the TypeInfo
	 * @param resolve true to resolve the TypeInfo if it happens to be a ClassTypeInfo
	 * @return the TypeInfo at the address
	 */
	TypeInfo getTypeInfo(Address address, boolean resolve);

	/**
	 * Gets the type with a class data type that has the provided id
	 * @param id the universal id
	 * @return the type with the corresponding data type id or null
	 */
	ClassTypeInfoDB getType(UniversalID id);

	@Override
	default void addListener(DomainObjectListener listener) {
		getProgram().addListener(listener);
	}

	@Override
	default void removeListener(DomainObjectListener listener) {
		getProgram().removeListener(listener);
	}

}
