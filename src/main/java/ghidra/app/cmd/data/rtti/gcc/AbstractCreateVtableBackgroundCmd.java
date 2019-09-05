package ghidra.app.cmd.data.rtti.gcc;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.data.DataType;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.app.cmd.data.rtti.gcc.vtable.VtableDataType;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;

import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.data.DataUtilities.ClearDataMode;

public abstract class AbstractCreateVtableBackgroundCmd extends BackgroundCommand {

    private VtableModel vtable;
    private TaskMonitor monitor;
    private Program program;

    private static final DemanglerOptions OPTIONS = new DemanglerOptions();

    protected AbstractCreateVtableBackgroundCmd(VtableModel vtable, String name) {
        super(name, true, true, false);
        this.vtable = vtable;
    }

    @Override
    public boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
        try {
            if (!(obj instanceof Program)) {
                String message = "Can only apply a vtable data type to a program.";
                Msg.error(this, message);
                return false;
            }
            program = (Program) obj;
            monitor = taskMonitor;
            return doApplyTo();
        } catch (CancelledException e) {
            setStatusMsg("User cancelled " + getName() + ".");
            return false;
        }
    }

    private boolean doApplyTo() throws CancelledException {
        try {
            monitor.checkCanceled();
            Data data = program.getListing().getDataAt(vtable.getAddress());
            if (data != null && data.getDataType() instanceof VtableDataType) {
                Symbol symbol = data.getPrimarySymbol();
                if (symbol != null) {
                    String name = symbol.getName();
                    if (name.equals(VtableModel.SYMBOL_NAME)
                        || name.equals(VtableModel.CONSTRUCTION_SYMBOL_NAME)) {
                            return true;
                        }
                }
                return createAssociatedData();
            }
            createData(vtable.getDataType());
            return createAssociatedData();
        } catch (CodeUnitInsertionException | InvalidDataTypeException e) {
            Msg.error(this, e);
            return false;
        }
    }

    private Data createData(DataType dt) throws CodeUnitInsertionException {
        Data data = program.getListing().getDataContaining(vtable.getAddress());
        if (data != null && data.getAddress().equals(vtable.getAddress())) {
            if (data.getDataType() instanceof VtableDataType) {
                return data;
            }
        }
        return DataUtilities.createData(
            program, vtable.getAddress(), dt, 0, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
    }

    protected abstract String getMangledString() throws InvalidDataTypeException;
    protected abstract String getSymbolName();

    private boolean createAssociatedData() {
        try {
            DemangledObject demangled = DemanglerUtil.demangle(program, getMangledString());
             return demangled.applyTo(program, vtable.getAddress(), OPTIONS, monitor);
        } catch (Exception e) {
            return false;
        }
    }
}
