package ghidra.app.cmd.data.rtti;

import ghidra.util.task.TaskMonitor;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.ClassTypeInfoModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;

/**
 * Interface for modeling std::type_info and its derivatives.
 * <br>
 * All derived models are based on dwarf information from libstdc++.a
 */
public interface ClassTypeInfo extends TypeInfo {

    public static final ClassTypeInfo INVALID = ClassTypeInfoModel.INVALID;

    
    default DataType getRepresentedDataType() {
        return getClassDataType();
    }

    /**
     * Gets the corresponding Ghidra Class for this TypeInfo and
     * creates it if none exists.
     * @return The class representation of this TypeInfo instance
     */
    GhidraClass getGhidraClass();

    boolean hasParent();

    /**
	 * Retrieves the Models of this ClassTypeInfo classes base classes.
	 * 
     */ 
    ClassTypeInfo[] getParentModels();

    /**
     * Determines if the represented class is an abstract base.
     * @return true if abstract;
     */
    boolean isAbstract();

    /**
     * Gets the TypeInfo's Vtable Model
     * 
     * @param TaskMonitor the taskmonitor to be used while searching for the vtable
     * @return The TypeInfo's Vtable Model or null if none exists
     */
    Vftable getVtable(TaskMonitor monitor) throws CancelledException;

    /**
     * Gets the TypeInfo's Vtable Model
     * 
     * @return The TypeInfo's Vtable Model or null if none exists
     */
    default Vftable getVtable() {
        try {
            return getVtable(new DummyCancellableTaskMonitor());
        }
        catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Gets the underlying structure of the class for this type_info
     * 
     * @return the structure datatype for this class.
     */
    default Structure getClassDataType() {
        return getClassDataType(false);
    }

    /**
     * Gets the underlying structure of the class for this type_info
     * 
     * @param repopulate true to re-insert the correct inherited components.
     * @return the structure datatype for this class.
     */
    Structure getClassDataType(boolean repopulate);

    /**
     * Gets a unique typename for this ClassTypeInfo instance.
     * The resulting string should be identical across all architectures and binaries.
     * 
     * @return a unique typename string.
     */
    String getUniqueTypeName();
    
}