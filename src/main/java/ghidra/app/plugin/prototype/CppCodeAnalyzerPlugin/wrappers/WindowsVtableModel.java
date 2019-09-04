package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.wrappers;

import java.util.List;
import java.util.ArrayList;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.cmd.data.rtti.Vftable;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

public class WindowsVtableModel implements Vftable {

    private Program program;
    private List<VfTableModel> vftables;
    private ClassTypeInfo type;
    private ClassTypeInfo[] parents;

    private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

    public WindowsVtableModel(Program program, List<Address> addresses,
        ClassTypeInfo[] parents, ClassTypeInfo type) {
            this.program = program;
            this.vftables = new ArrayList<>(addresses.size());
            this.parents = parents;
            this.type = type;
            for (Address address : addresses) {
                vftables.add(
                    new VfTableModel(program, address, DEFAULT_OPTIONS));
            }
    }

    @Override
    public ClassTypeInfo getTypeInfo() {
        return type;
    }

    @Override
    public boolean isValid() {
        return getTypeInfo().isValid();
    }

    @Override
    public Address[] getTableAddresses() {
        Address[] addresses = new Address[vftables.size()];
        for (int i = 0; i < addresses.length; i++) {
            addresses[i] = vftables.get(i).getAddress();
        }
        return addresses;
    }

    private Function[] getFunctions(VfTableModel vftable) {
        Function[] functions = new Function[vftable.getElementCount()];
        FunctionManager manager = program.getFunctionManager();
        for (int i = 0; i < vftable.getElementCount(); i++) {
            functions[i] = manager.getFunctionAt(vftable.getVirtualFunctionPointer(i));
        }
        return functions;
    }

    @Override
    public Function[][] getFunctionTables() {
        List<Function[]> tables = new ArrayList<>(vftables.size());
        for (VfTableModel vftable : vftables) {
            tables.add(getFunctions(vftable));
        }
        return tables.toArray(new Function[tables.size()][]);
    }

    protected List<VfTableModel> getVfTables() {
        return vftables;
    }

    @Override
    public boolean containsFunction(Function function) {
        for (Function[] functionTables : getFunctionTables()) {
            for (Function vFunction : functionTables) {
                if (vFunction.equals(function)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public ClassTypeInfo getBaseClassTypeInfo(int i) {
		if (i < parents.length) {
            return parents[i];
        }
        return null;
	}

	@Override
	public DataType getDataType() {
		throw new UnsupportedOperationException();
	}
}
