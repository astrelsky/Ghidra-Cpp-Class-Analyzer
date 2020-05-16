package ghidra.program.database.data.rtti;

import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

public interface ClassTypeInfoManager {

	public static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	String getName();

	ClassTypeInfoDB resolve(ClassTypeInfo type);

	ClassTypeInfoDB getType(GhidraClass gc) throws UnresolvedClassTypeInfoException;
	ClassTypeInfoDB getType(Function fun) throws UnresolvedClassTypeInfoException;
	ClassTypeInfoDB getType(String name, Namespace namespace)
		throws UnresolvedClassTypeInfoException;
	ClassTypeInfoDB getType(String typeName) throws UnresolvedClassTypeInfoException;

	Iterable<ClassTypeInfoDB> getTypes();
	Stream<ClassTypeInfoDB> getTypeStream();
	int getTypeCount();
}