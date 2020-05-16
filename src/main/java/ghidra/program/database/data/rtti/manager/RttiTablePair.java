package ghidra.program.database.data.rtti.manager;

import java.io.IOException;

import db.Table;

final class RttiTablePair {

	private final Table classTable;
	private final Table vtableTable;

	RttiTablePair(Table classTable, Table vtableTable) {
		this.classTable = classTable;
		this.vtableTable = vtableTable;
	}

	static String getName(Table table) {
		String name = table.getName();
		return name.substring(0, name.indexOf(' '));
	}

	String getName() {
		return getName(classTable);
	}

	Table getTypeTable() {
		return classTable;
	}

	Table getVtableTable() {
		return vtableTable;
	}

	void deleteAll() throws IOException {
		classTable.deleteAll();
		vtableTable.deleteAll();
	}
}