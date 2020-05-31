package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;

final class TypeInfoLibraryNode extends AbstractSingleManagerNode {

	TypeInfoLibraryNode(LibraryClassTypeInfoManager manager) {
		super(manager);
	}

}