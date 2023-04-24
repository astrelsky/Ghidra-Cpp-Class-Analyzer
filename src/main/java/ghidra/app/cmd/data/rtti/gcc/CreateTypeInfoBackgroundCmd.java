package ghidra.app.cmd.data.rtti.gcc;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.data.DataType;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.data.DataUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.util.CodeUnitInsertionException;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA;


public class CreateTypeInfoBackgroundCmd extends BackgroundCommand {

	private static final String NAME = CreateTypeInfoBackgroundCmd.class.getSimpleName();
	private static final DemanglerOptions OPTIONS = new DemanglerOptions();

	private TypeInfo type;
	private TaskMonitor monitor;
	private Program program;

	/**
	 * Constructs a command for applying a TypeInfo at an address
	 * and its associated data.
	 *
	 * @param typeInfo the TypeInfo to be created.
	 */
	public CreateTypeInfoBackgroundCmd(TypeInfo typeInfo) {
		super(NAME, true, true, false);
		this.type = typeInfo;
	}

	@Override
	public final boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
		try {
			if (!(obj instanceof Program)) {
				String message = "Can only apply a " + type.getName() + " data type to a program.";
				Msg.error(this, message);
				return false;
			}
			program = (Program) obj;
			monitor = taskMonitor;
			return doApplyTo();
		} catch (CancelledException e) {
			setStatusMsg("User cancelled " + getName() + ".");
		}
		return false;
	}

	private boolean doApplyTo() throws CancelledException {
		try {
			monitor.checkCancelled();
			Data data = createData(type.getAddress(), type.getDataType());
			if (type.getIdentifier().equals(VmiClassTypeInfoModel.ID_STRING)) {
				DataType array = VmiClassTypeInfoModel.getBaseArrayDataType(data);
				Address arrayAddress = type.getAddress().add(data.getLength());
				createData(arrayAddress, array);
			}
			return applyTypeInfoSymbols() && data != null;
		} catch (CodeUnitInsertionException e) {
			Msg.error(this, e);
		} catch (RuntimeException e) {
			Throwable cause = e.getCause();
			if (cause instanceof MemoryAccessException) {
				Address addr = type.getAddress();
				if (addr != null) {
					Msg.error(this, "Failed to apply typeinfo at "+type.getAddress().toString(), cause);
				} else {
					Msg.error(this, "Failed to apply typeinfo because it's address is null", cause);
				}
			}
		}
		return false;
	}

	private Data createData(Address address, DataType dt) throws CodeUnitInsertionException {
		return DataUtilities.createData(program, address, dt, 0, false, CLEAR_ALL_CONFLICT_DATA);
	}

	private boolean applyTypeInfoSymbols() {
		Address typenameAddress = getAbsoluteAddress(
			program, type.getAddress().add(program.getDefaultPointerSize()));
		String typename = type.getTypeName();
		try {
			DemangledObject demangled = DemanglerUtil.demangle(program, "_ZTI" +typename);
			if (demangled != null) {
				demangled.applyTo(program, type.getAddress(), OPTIONS, monitor);
			}
			demangled = DemanglerUtil.demangle(program, "_ZTS" +typename);
			if (demangled != null) {
				demangled.applyTo(program, typenameAddress, OPTIONS, monitor);
			}
			return true;
		} catch (Exception e) {
			setStatusMsg(e.getMessage());
			return false;
		}
	}
}
