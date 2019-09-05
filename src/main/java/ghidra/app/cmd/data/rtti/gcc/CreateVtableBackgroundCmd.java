package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.Msg;

public class CreateVtableBackgroundCmd extends AbstractCreateVtableBackgroundCmd {

    private static final String NAME = CreateVtableBackgroundCmd.class.getSimpleName();

    private static final String SYMBOL_NAME = "vtable";

    private TypeInfo type;

    public CreateVtableBackgroundCmd(VtableModel vtable) {
        super(vtable, NAME);
        try {
            this.type = vtable.getTypeInfo();
        } catch (InvalidDataTypeException e) {
            Msg.error(this, e);
        }
    }

    @Override
    protected String getSymbolName() {
        return SYMBOL_NAME;
    }

    @Override
    protected String getMangledString() throws InvalidDataTypeException {
        return VtableModel.MANGLED_PREFIX+type.getTypeName();
    }
}