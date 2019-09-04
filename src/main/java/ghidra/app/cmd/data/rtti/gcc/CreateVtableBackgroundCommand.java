package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.TypeInfo;


public class CreateVtableBackgroundCommand extends AbstractCreateVtableBackgroundCommand {

    private static final String SYMBOL_NAME = "vtable";
    private static final String NAME = "Create Vtable Background Command";

    private String typename;

    public CreateVtableBackgroundCommand(VtableModel vtable) {
        super(vtable, NAME);
        TypeInfo type = vtable.getTypeInfo();
        this.typename = type.getTypeName();
    }

    @Override
    protected String getSymbolName() {
        return SYMBOL_NAME;
    }

    @Override
    protected String getMangledString() {
        return VtableModel.MANGLED_PREFIX+typename;
    }
}
