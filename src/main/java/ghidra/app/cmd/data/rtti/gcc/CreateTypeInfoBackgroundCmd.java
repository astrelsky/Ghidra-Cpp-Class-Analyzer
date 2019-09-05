package ghidra.app.cmd.data.rtti.gcc;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.data.DataType;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.program.model.util.CodeUnitInsertionException;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA;


public class CreateTypeInfoBackgroundCmd extends BackgroundCommand {

    private static final String NAME = CreateTypeInfoBackgroundCmd.class.getSimpleName();

    private TypeInfo typeInfo;
    private TaskMonitor monitor;
    private Program program;
    private String typename;

    private Exception exception;

    private static final DemanglerOptions OPTIONS = new DemanglerOptions();

    private static final String NAME_PREFIX = "_ZTS";
    private static final String TYPE_INFO_PREFIX = "_ZTI";


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

    public Exception getException() {
        return exception;
    }

    private boolean doApplyTo() throws CancelledException, InvalidDataTypeException {
        try {
            monitor.checkCanceled();
            typename = typeInfo.getTypeName();
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

    private boolean applyTypeInfoSymbols() throws CancelledException {
        DemangledObject[] demangledObjects = new DemangledObject[]{
            DemanglerUtil.demangle(TYPE_INFO_PREFIX+typename),
            DemanglerUtil.demangle(NAME_PREFIX+typename),
        };
        Address[] addresses  = new Address[]{
            typeInfo.getAddress(),
            getAbsoluteAddress(program, typeInfo.getAddress().add(program.getDefaultPointerSize()))
        };
        for (int i = 0; i < demangledObjects.length; i++) {
            monitor.checkCanceled();
            try {
                demangledObjects[i].applyTo(program, addresses[i], OPTIONS, monitor);
                Symbol[] symbols = program.getSymbolTable().getSymbols(addresses[i]);
                for (Symbol symbol : symbols) {
                    if (symbol.getName(true).equals(demangledObjects[i].getDemangledName())) {
                        symbol.setPrimary();
                    }
                }
            } catch (Exception e) {
                Msg.error(this, e);
                return false;
            }
        }
        return true;
    }
}
