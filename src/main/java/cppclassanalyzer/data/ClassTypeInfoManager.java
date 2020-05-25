package cppclassanalyzer.data;

import java.util.stream.Stream;

import javax.swing.Icon;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.prototype.typemgr.node.TypeInfoTreeNodeManager;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import db.util.ErrorHandler;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

public interface ClassTypeInfoManager extends ErrorHandler {

	public static final long INVALID_KEY = AddressMap.INVALID_ADDRESS_KEY;

	String getName();

	Icon getIcon(boolean expanded);

	ClassTypeInfoDB resolve(ClassTypeInfo type);
	ClassTypeInfoDB getType(long key);
	ClassTypeInfoDB getType(GhidraClass gc) throws UnresolvedClassTypeInfoException;
	ClassTypeInfoDB getType(Function fun) throws UnresolvedClassTypeInfoException;
	ClassTypeInfoDB getType(String name, Namespace namespace)
		throws UnresolvedClassTypeInfoException;
	ClassTypeInfoDB getType(String typeName) throws UnresolvedClassTypeInfoException;

	Iterable<ClassTypeInfoDB> getTypes();
	Stream<ClassTypeInfoDB> getTypeStream();
	int getTypeCount();

	TypeInfoTreeNodeManager getTreeNodeManager();
}