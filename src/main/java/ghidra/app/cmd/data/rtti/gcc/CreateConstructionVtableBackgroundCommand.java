package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;


public class CreateConstructionVtableBackgroundCommand extends AbstractCreateVtableBackgroundCommand {

    private static final String NAME = "Create Construction Vtable Command";

    private TypeInfo parent;
    private TypeInfo child;

    private static final String PREFIX = "_ZTC";
    private static final String SEPARATOR = "_";
    
    public CreateConstructionVtableBackgroundCommand(VtableModel vtable, ClassTypeInfo child) {
            super(vtable, NAME);
            this.parent = vtable.getTypeInfo();
            this.child = child;
    }

    @Override
    protected String getSymbolName() {
        return VtableModel.CONSTRUCTION_SYMBOL_NAME;
    }

    @Override
    protected String getMangledString() {
        // parent-in-child
        return PREFIX+parent.getTypeName()+SEPARATOR+child.getTypeName();
    }
}
