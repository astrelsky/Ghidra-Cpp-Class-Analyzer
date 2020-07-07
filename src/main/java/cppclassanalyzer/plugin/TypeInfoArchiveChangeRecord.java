package cppclassanalyzer.plugin;

import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;

public class TypeInfoArchiveChangeRecord {

	private final ChangeType changeType;
	private final ClassTypeInfoDB type;

	public TypeInfoArchiveChangeRecord(ChangeType changeType, ClassTypeInfoDB type) {
		this.changeType = changeType;
		this.type = type;
	}

	public ChangeType getChangeType() {
		return changeType;
	}

	public ClassTypeInfoDB getType() {
		return type;
	}

	public static enum ChangeType {
		TYPE_ADDED,
		TYPE_REMOVED,
		TYPE_UPDATED
	};
}
