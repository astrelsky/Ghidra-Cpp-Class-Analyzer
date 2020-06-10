package ghidra.app.plugin.prototype.typemgr.node;

import ghidra.app.util.SymbolPath;
import ghidra.util.Lock;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.database.record.TypeInfoTreeNodeRecord;
import cppclassanalyzer.database.schema.TypeInfoTreeNodeSchema;
import cppclassanalyzer.database.tables.TypeInfoTreeNodeTable;
import db.DBHandle;
import db.DBListener;
import db.StringField;
import db.Table;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

import static cppclassanalyzer.database.record.TypeInfoTreeNodeRecord.*;
import static cppclassanalyzer.database.schema.TypeInfoTreeNodeSchema.INDEXED_COLUMNS;
import static cppclassanalyzer.database.schema.fields.TypeInfoTreeNodeSchemaFields.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class TypeInfoTreeNodeManager implements DBListener {

	private final TypeInfoTreeNodeTable table;
	private final ClassTypeInfoManager manager;
	private final TransactionHandler handler;
	private final DBHandle handle;
	private final Lock lock = new Lock(getClass().getSimpleName());
	private AbstractManagerNode root;

	public TypeInfoTreeNodeManager(ClassTypeInfoManager manager, DBHandle handle) {
		this(manager, TypeInfoTreeNodeManager.class.getSimpleName(), handle);
	}

	public TypeInfoTreeNodeManager(ClassTypeInfoManager manager, DBHandle handle, String name) {
		this(manager, name + " " + TypeInfoTreeNodeManager.class.getSimpleName(), handle);
	}

	private TypeInfoTreeNodeManager(ClassTypeInfoManager manager, String name, DBHandle handle) {
		this.handle = handle;
		this.manager = manager;
		this.handler = new TransactionHandler(handle);
		this.table = getTable(name);
		handle.addListener(this);
	}

	private TypeInfoTreeNodeTable getTable(String name) {
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
		TypeInfoTreeNodeRecord record = getRecord("/");
		if (record == null) {
			record = createRootRecord();
		}
		return record;
	}

	void setRootNode(AbstractManagerNode node) {
		this.root = node;
	}

	private TypeInfoTreeNodeRecord createRootRecord() {
		TypeInfoTreeNodeRecord record = createRecord();
		record.setStringValue(NAME, "Root");
		record.setStringValue(SYMBOL_PATH, "/");
		updateRecord(record);
		return record;
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
				if (parent == null) {
					TypeInfoTreeNode node =
						(TypeInfoTreeNode) createNamespaceNode(parentPath.asList());
					parent = node.getRecord();
				}
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

	GTreeNode createNamespaceNode(List<String> paths) {
		TypeInfoTreeNodeRecord record =
			createRecord(paths, TypeInfoTreeNodeRecord.NAMESPACE_NODE);
		return new NamespacePathNode(this, record);
	}

	GTreeNode createTypeNode(List<String> paths, ClassTypeInfoDB type) {
		TypeInfoTreeNodeRecord record =
			createRecord(paths, TypeInfoTreeNodeRecord.TYPEINFO_NODE);
		record.setLongValue(TYPE_KEY, type.getKey());
		updateRecord(record);
		return new TypeInfoNode(type, record);
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

	private GTreeNode fastGetNode(TypeInfoTreeNodeRecord record) {
		if (root == null) {
			// don't bother
			return null;
		}
		long rootKey = root.getKey();
		long key = record.getKey();
		LinkedList<String> paths = new LinkedList<>();
		while (key != rootKey) {
			TypeInfoTreeNodeRecord parentRecord = getRecord(key);
			paths.add(parentRecord.getStringValue(NAME));
			key = parentRecord.getLongValue(PARENT_KEY);
		}
		GTreeNode node = (GTreeNode) root;
		for (String path : (Iterable<String>) () -> paths.descendingIterator()) {
			if (node == null) {
				return null;
			}
			node = node.getChild(path);
		}
		return node != root ? node : null;
	}

	GTreeNode createNode(TypeInfoTreeNodeRecord record) {
		long key = record.getLongValue(TYPE_KEY);
		switch (record.getByteValue(TYPE_ID)) {
			case NAMESPACE_NODE:
				return new NamespacePathNode(this, record);
			case TYPEINFO_NODE:
				return new TypeInfoNode(manager.getType(key), record);
			default:
				throw new AssertException("Unknown TypeInfoTreeNode ID");
		}
	}

	public GTreeNode getNode(TypeInfoTreeNodeRecord record) {
		GTreeNode node = fastGetNode(record);
		if (node != null) {
			return node;
		}
		return createNode(record);
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

	GTree getTree() {
		if (root == null) {
			return null;
		}
		return ((GTreeNode) root).getTree();
	}

	List<GTreeNode> generateChildren(TypeInfoTreeNode node, TaskMonitor monitor)
			throws CancelledException {
		TypeInfoTreeNodeRecord record = node.getRecord();
		long[] keys = record.getLongArray(CHILDREN_KEYS);
		List<GTreeNode> children = new ArrayList<>(keys.length);
		monitor.initialize(keys.length);
		for (long key : keys) {
			monitor.checkCanceled();
			TypeInfoTreeNodeRecord child = getRecord(key);
			children.add(createNode(child));
			monitor.incrementProgress(1);
		}
		children.sort(null);
		return children;
	}

	private void refresh() {
		this.root = root.rebuild();
	}

	@Override
	public void dbRestored(DBHandle dbh) {
		if (handle.equals(dbh)) {
			SystemUtilities.runSwingLater(this::refresh);
		}
	}

	@Override
	public void dbClosed(DBHandle dbh) {
		// let the plugin handle it
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table table) {
	}

	@Override
	public void tableAdded(DBHandle dbh, Table table) {
	}

	// dbHandle transactions are different
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