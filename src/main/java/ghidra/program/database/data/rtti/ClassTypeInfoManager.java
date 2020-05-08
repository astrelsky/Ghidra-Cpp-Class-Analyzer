package ghidra.program.database.data.rtti;

import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

public interface ClassTypeInfoManager {

	ClassTypeInfo getType(GhidraClass gc) throws UnresolvedClassTypeInfoException;
	ClassTypeInfo getType(Function fun) throws UnresolvedClassTypeInfoException;
	ClassTypeInfo getType(String name, Namespace namespace)
		throws UnresolvedClassTypeInfoException;
	ClassTypeInfo getType(String typeName) throws UnresolvedClassTypeInfoException;

	Iterable<ClassTypeInfo> getTypes();
	Stream<ClassTypeInfo> getTypeStream();
	int getTypeCount();
}