package cppclassanalyzer.data.manager;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import cppclassanalyzer.data.manager.caches.ProgramRttiCachePair;
import cppclassanalyzer.data.manager.tables.ProgramRttiTablePair;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.VsClassTypeInfoDB;
import cppclassanalyzer.data.vtable.VftableDB;
import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.vs.RttiModelWrapper;
import cppclassanalyzer.vs.VsClassTypeInfo;
import cppclassanalyzer.vs.VsVtableModel;

public final class VsClassTypeInfoManager extends ClassTypeInfoManagerDB {

	public VsClassTypeInfoManager(ClassTypeInfoManagerService service, ProgramDB program) {
		super(service, program);
	}

	@Override
	protected RttiRecordWorker getWorker(ProgramRttiTablePair tables,
			ProgramRttiCachePair caches) {
		return new WindowsRttiRecordWorker(tables, caches);
	}

	private static boolean isRtti4Model(Data data) {
		if (data == null) {
			return false;
		}
		return data.getMnemonicString().equals(VsClassTypeInfo.LOCATOR_SYMBOL_NAME);
	}

	@Override
	public ClassTypeInfoDB getType(Address address) {
		Data data = program.getListing().getDataAt(address);
		if (isRtti4Model(data)) {
			Rtti4Model model =
				new Rtti4Model(program, address, VsClassTypeInfo.DEFAULT_OPTIONS);
			try {
				address = model.getRtti0Address();
			} catch (InvalidDataTypeException e) {
				throw new AssertException(e);
			}
		}
		return super.getType(address);
	}

	@Override
	public ClassTypeInfoDB getType(GhidraClass gc) {
		// this isn't reliable but now required for vs binaries
		DataType dt =
			VariableUtilities.findOrCreateClassStruct(gc, program.getDataTypeManager());
		return getType(dt.getUniversalID());
	}

	@Override
	public TypeInfo getTypeInfo(Address address, boolean resolve) {
		TypeInfo ti = super.getTypeInfo(address, resolve);
		if (ti == null) {
			TypeDescriptorModel model =
				new TypeDescriptorModel(program, address, VsClassTypeInfo.DEFAULT_OPTIONS);
			try {
				ti = RttiModelWrapper.getWrapper(model, TaskMonitor.DUMMY);
			} catch (CancelledException e) {
				throw new AssertException(e);
			}
		}
		if (ti instanceof ClassTypeInfo && resolve) {
			ti = resolve((ClassTypeInfo) ti);
		}
		return ti;
	}

	@Override
	public boolean isTypeInfo(Address address) {
		try {
			TypeDescriptorModel model =
				new TypeDescriptorModel(program, address, VsClassTypeInfo.DEFAULT_OPTIONS);
			model.validate();
			return true;
		} catch (InvalidDataTypeException e) {
			// do nothing
		}
		return false;
	}

	private final class WindowsRttiRecordWorker extends RttiRecordWorker {

		WindowsRttiRecordWorker(ProgramRttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		VsClassTypeInfoDB buildType(ClassTypeInfoRecord record) {
			return new VsClassTypeInfoDB(this, record);
		}

		@Override
		VsClassTypeInfoDB buildType(ClassTypeInfo type, ClassTypeInfoRecord record) {
			return new VsClassTypeInfoDB(this, (VsClassTypeInfo) type, record);
		}

		@Override
		VftableDB buildVtable(VtableRecord record) {
			return new VftableDB(this, record);
		}

		@Override
		VftableDB buildVtable(Vtable vtable, VtableRecord record) {
			return new VftableDB(this, (VsVtableModel) vtable, record);
		}

	}

}
