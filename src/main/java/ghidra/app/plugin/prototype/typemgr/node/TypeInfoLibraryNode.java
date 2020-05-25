package ghidra.app.plugin.prototype.typemgr.node;

import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;

final class TypeInfoLibraryNode extends AbstractManagerNode {

	TypeInfoLibraryNode(LibraryClassTypeInfoManager manager) {
		super(manager);
	}

	@Override
	public String getToolTip() {
		return null;
	}

}