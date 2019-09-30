package ghidra.app.cmd.data.rtti.gcc;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.data.DataType;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.program.model.util.CodeUnitInsertionException;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA;


public class CreateTypeInfoBackgroundCmd extends BackgroundCommand {

    private static final String NAME = CreateTypeInfoBackgroundCmd.class.getSimpleName();

    private TypeInfo typeInfo;
    private TaskMonitor monitor;
    private Program program;

    /**
     * Constructs a command for applying a TypeInfo at an address
     * and its associated data.
     * 
     * @param TypeInfo the TypeInfo to be created.
     * @param address the address where the data should be created.
     */
    public CreateTypeInfoBackgroundCmd(TypeInfo typeInfo) {
        super(NAME, true, true, false);
        this.typeInfo = typeInfo;
    }

    @Override
    public final boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
        try {
            if (!(obj instanceof Program)) {
                String message = "Can only apply a " + typeInfo.getName() + " data type to a program.";
                Msg.error(this, message);
                return false;
            }
            program = (Program) obj;
            monitor = taskMonitor;
            typeInfo.validate();
            return doApplyTo();
        } catch (CancelledException e) {
            setStatusMsg("User cancelled " + getName() + ".");
            return false;
        } catch (InvalidDataTypeException e) {
            setStatusMsg(e.getMessage());
            return false;
        }
    }

    private boolean doApplyTo() throws CancelledException, InvalidDataTypeException {
        try {
            monitor.checkCanceled();
            Data data = createData(typeInfo.getAddress(), typeInfo.getDataType());
            if (typeInfo instanceof VmiClassTypeInfoModel) {
                VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) typeInfo;
                DataType array = vmi.getBaseArrayDataType();
                Address arrayAddress = vmi.getBaseArrayAddress();
                createData(arrayAddress, array);
            }
            return applyTypeInfoSymbols() && data != null;
        } catch (CodeUnitInsertionException e) {
            Msg.error(this, e);
            return false;
        }
    }

    private Data createData(Address address, DataType dt) throws CodeUnitInsertionException {
        return DataUtilities.createData(program, address, dt, 0, false, CLEAR_ALL_CONFLICT_DATA);
    }

    private boolean applyTypeInfoSymbols() throws InvalidDataTypeException {
        SymbolTable table = program.getSymbolTable();
        Namespace ns = typeInfo.getNamespace();
        Address typenameAddress = getAbsoluteAddress(
            program, typeInfo.getAddress().add(program.getDefaultPointerSize()));
        try {
            table.createLabel(typeInfo.getAddress(), TypeInfo.SYMBOL_NAME, ns, SourceType.ANALYSIS);
            table.createLabel(typenameAddress, TypeInfo.SYMBOL_NAME+"_name", ns, SourceType.ANALYSIS);
        } catch (InvalidInputException e) {
            Msg.trace(this, e);
            return false;
        }
        return true;
    }
}
