package ghidra.app.plugin.prototype.typemgr.node;

import ghidra.app.util.SymbolPath;
import ghidra.util.Lock;
import ghidra.util.exception.AssertException;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import cppclassanalyzer.database.schema.TypeInfoTreeNodeSchema;
import cppclassanalyzer.database.tables.TypeInfoTreeNodeTable;
import db.DBHandle;
import db.StringField;
import db.Table;
import docking.widgets.tree.GTreeNode;

import static cppclassanalyzer.database.record.TypeInfoTreeNodeRecord.*;
import static cppclassanalyzer.database.schema.TypeInfoTreeNodeSchema.INDEXED_COLUMNS;
import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

import java.io.IOException;
import java.util.List;

public class TypeInfoTreeNodeManager {

	private final TypeInfoTreeNodeTable table;
	private final ClassTypeInfoManager manager;
	private final TransactionHandler handler;
	private final Lock lock = new Lock(getClass().getSimpleName());

	public TypeInfoTreeNodeManager(ClassTypeInfoManager manager, DBHandle handle) {
		this.manager = manager;
		this.handler = new TransactionHandler(handle);
		this.table = getTable(handle, getClass().getSimpleName());
		createRootRecord();
	}

	public TypeInfoTreeNodeManager(ClassTypeInfoManager manager, DBHandle handle, String name) {
		this.manager = manager;
		this.handler = new TransactionHandler(handle);
		this.table = getTable(handle, name + " " + getClass().getSimpleName());
		createRootRecord();
	}

	private TypeInfoTreeNodeTable getTable(DBHandle handle, String name) {
		Table rawTable = handle.getTable(name);
		if (rawTable == null) {
			try {
				handler.start();
				rawTable = handle.createTable(
					name,
					TypeInfoTreeNodeSchema.SCHEMA,
					TypeInfoTreeNodeSchema.INDEXED_COLUMNS
				);
				handler.end();
			} catch (IOException e) {
				dbError(e);
			}
		}
		return new TypeInfoTreeNodeTable(rawTable);
	}

	TypeInfoTreeNodeRecord getRootRecord() {
		return getRecord("/");
	}

	private void createRootRecord() {
		TypeInfoTreeNodeRecord record = createRecord();
		record.setStringValue(NAME, "/");
		updateRecord(record);
	}

	TypeInfoTreeNodeRecord createRecord(List<String> paths, byte type) {
		lock.acquire();
		try {
			SymbolPath path = new SymbolPath(paths);
			TypeInfoTreeNodeRecord record = createRecord();
			record.setStringValue(SYMBOL_PATH, path.getPath());
			record.setStringValue(NAME, path.getName());
			record.setByteValue(TYPE_ID, type);
			SymbolPath parentPath = path.getParent();
			if (parentPath != null) {
				TypeInfoTreeNodeRecord parent = getRecord(parentPath);
				record.setLongValue(PARENT_KEY, parent.getKey());
			} else {
				record.setLongValue(PARENT_KEY, -1);
			}
			updateRecord(record);
			return record;
		} finally {
			lock.release();
		}
	}

	public TypeInfoTreeNodeRecord getRecord(long key) {
		lock.acquire();
		try {
			return table.getRecord(key);
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		return null;
	}

	public TypeInfoTreeNodeRecord getRecord(SymbolPath path) {
		return getRecord(path.getPath());
	}

	private TypeInfoTreeNodeRecord getRecord(String path) {
		lock.acquire();
		try {
			StringField field = new StringField(path);
			long[] keys = table.getTable().findRecords(field, INDEXED_COLUMNS[0]);
			if (keys.length == 1) {
				return table.getRecord(keys[0]);
			}
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		return null;
	}

	TypeInfoTreeNodeRecord createRecord() {
		lock.acquire();
		try {
			handler.start();
			long key = table.getTable().getKey();
			TypeInfoTreeNodeSchema schema = table.getSchema();
			db.Record record = schema.createRecord(key);
			table.getTable().putRecord(record);
			handler.end();
			return schema.getRecord(record);
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
		return null;
	}

	GTreeNode getNode(SymbolPath path) {
		lock.acquire();
		try {
			TypeInfoTreeNodeRecord record = getRecord(path);
			if (record != null) {
				return getNode(record);
			}
		} finally {
			lock.release();
		}
		return null;
	}

	private void dbError(IOException e) {
		manager.dbError(e);
	}

	public GTreeNode getNode(TypeInfoTreeNodeRecord record) {
		long key = record.getLongValue(TYPE_KEY);
		switch (record.getByteValue(TYPE_ID)) {
			case NAMESPACE_NODE:
				return new NamespacePathNode(this, record);
			case TYPEINFO_NODE:
				return new TypeInfoNode(manager.getType(key), record);
			case NESTED_NODE:
				ClassTypeInfoDB type = manager.getType(key);
				NamespacePathNode nested = new NamespacePathNode(this, record);
				return new TypeInfoNode(type, nested, record);
			default:
				throw new AssertException("Unknown TypeInfoTreeNode ID");
		}
	}

	public void updateRecord(TypeInfoTreeNodeRecord record) {
		lock.acquire();
		try {
			handler.start();
			table.getTable().putRecord(record.getRecord());
			handler.end();
		} catch (IOException e) {
			dbError(e);
		} finally {
			lock.release();
		}
	}

	ClassTypeInfoManager getManager() {
		return manager;
	}

	private static class TransactionHandler {
		final DBHandle handle;
		long id;

		TransactionHandler(DBHandle handle) {
			this.handle = handle;
			this.id = -1;
		}

		void start() {
			id = handle.isTransactionActive() ? -1 : handle.startTransaction();
		}

		void end() throws IOException {
			if (id != -1) {
				handle.endTransaction(id, true);
			}
		}
	}
}