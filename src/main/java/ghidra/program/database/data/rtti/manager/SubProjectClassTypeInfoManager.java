package ghidra.program.database.data.rtti.manager;

import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.database.data.rtti.ClassTypeInfoManager;
import ghidra.program.database.data.rtti.manager.caches.ArchivedRttiCachePair;
import ghidra.program.database.data.rtti.typeinfo.ClassTypeInfoDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

class SubProjectClassTypeInfoManager implements ClassTypeInfoManager {

	private final ProjectClassTypeInfoManager manager;
	private final RttiRecordWorker worker;
	private final String name;

	SubProjectClassTypeInfoManager(ProjectClassTypeInfoManager manager, RttiTablePair tables,
			String name) {
		this.manager = manager;
		this.worker = new RttiRecordWorker(tables, new ArchivedRttiCachePair());
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public ClassTypeInfoDB resolve(ClassTypeInfo type) {
		return worker.resolve(type);
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) {
		return worker.getType(gc);
	}

	@Override
	public ClassTypeInfoDB getType(Function fun) {
		return worker.getType(fun);
	}

	@Override
	public ClassTypeInfoDB getType(String name, Namespace namespace) {
		return worker.getType(name, namespace);
	}

	@Override
	public ClassTypeInfoDB getType(String symbolName) {
		return worker.getType(symbolName);
	}

	@Override
	public Iterable<ClassTypeInfoDB> getTypes() {
		return worker.getTypes();
	}

	@Override
	public Stream<ClassTypeInfoDB> getTypeStream() {
		return worker.getTypeStream();
	}

	@Override
	public int getTypeCount() {
		return worker.getTables().getTypeTable().getRecordCount();
	}

	private final class RttiRecordWorker extends ArchiveRttiRecordWorker {

		private int id = -1;

		RttiRecordWorker(RttiTablePair tables, ArchivedRttiCachePair caches) {
			super(manager, tables, caches);
		}

		@Override
		void acquireLock() {
			manager.acquireLock();
		}

		@Override
		void releaseLock() {
			manager.releaseLock();
		}

		@Override
		public void startTransaction(String description) {
			id = manager.startTransaction(description);
		}

		@Override
		public void endTransaction() {
			if (id != -1) {
				manager.endTransaction(id, true);
				id = -1;
			}
		}
	}

}