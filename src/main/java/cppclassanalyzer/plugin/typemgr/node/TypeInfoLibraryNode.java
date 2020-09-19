package cppclassanalyzer.plugin.typemgr.node;

import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

import cppclassanalyzer.data.manager.LibraryClassTypeInfoManager;

public final class TypeInfoLibraryNode extends AbstractSingleManagerNode {

	TypeInfoLibraryNode(LibraryClassTypeInfoManager manager) {
		super(manager);
	}

	@Override
	public boolean isEditable() {
		return true;
	}

	@Override
	public LibraryClassTypeInfoManager getTypeManager() {
		return (LibraryClassTypeInfoManager) super.getTypeManager();
	}

	@Override
	public void valueChanged(Object newValue) {
		if (newValue instanceof String) {
			LibraryClassTypeInfoManager manager = getTypeManager();
			try {
				manager.rename((String) newValue);
			} catch (InvalidNameException | DuplicateNameException e) {
				Msg.error(this, e);
			}
		}
	}
}
