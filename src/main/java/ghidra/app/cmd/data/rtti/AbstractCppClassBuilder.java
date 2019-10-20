package ghidra.app.cmd.data.rtti;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;

import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CompositeDataTypeElementInfo;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

abstract public class AbstractCppClassBuilder {

    protected static final String SUPER = "super_";
    private static final String ERROR_MESSAGE = "Invalid ClassTypeInfo. Class cannot be built";
    private static final String INTERFACE_DESCRIPTION = "Implemented Interfaces: ";
    private static final String INTERFACE_SEPARATOR = ", ";

    private Program program;
    protected Structure struct;
    private CategoryPath path;
    private ClassTypeInfo type;

    private Map<CompositeDataTypeElementInfo, String> dtComps = Collections.emptyMap();

    protected AbstractCppClassBuilder(ClassTypeInfo type) {
        this.type = type;
        try {
            GhidraClass gc = type.getGhidraClass();
            this.program = gc.getSymbol().getProgram();
            this.struct = ClassTypeInfoUtils.getPlaceholderStruct(
                type, program.getDataTypeManager());
            this.path = new CategoryPath(struct.getCategoryPath(), type.getName());
        } catch (InvalidDataTypeException e) {
            Msg.error(this, ERROR_MESSAGE);
        }
    }

    protected abstract AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent);

    protected final ClassTypeInfo getType() {
        return type;
    }

    protected final Program getProgram() {
        return program;
    }

    protected abstract Map<ClassTypeInfo, Integer> getBaseOffsets() throws InvalidDataTypeException;

    public Structure getDataType() throws InvalidDataTypeException {
        if (struct.isDeleted()) {
            struct = ClassTypeInfoUtils.getPlaceholderStruct(
                type, program.getDataTypeManager());
        }
        stashComponents();
        try {
            int i = 0;
            Map<ClassTypeInfo, Integer> baseMap = getBaseOffsets();
            for (ClassTypeInfo parent : baseMap.keySet()) {
                AbstractCppClassBuilder parentBuilder = getParentBuilder(parent);
                int offset = baseMap.get(parent);
                if (offset == 0 && 0 < i++) {
                    if (!parent.hasParent()) {
                        // it is an empty class, interface or essentially a namespace.
                        String description = struct.getDescription();
                        if (!description.contains(INTERFACE_DESCRIPTION)) {
                            StringBuilder builder = new StringBuilder(INTERFACE_DESCRIPTION);
                            builder.append(parent.getName());
                            struct.setDescription(builder.toString());
                        } else if (!description.contains(parent.getName())) {
                            StringBuilder builder = new StringBuilder(description);
                            builder.append(INTERFACE_SEPARATOR);
                            builder.append(parent.getName());
                            struct.setDescription(builder.toString());
                        }
                    } else {
                        String fieldName = struct.getComponent(0).getFieldName();
                        fieldName = fieldName.replace(SUPER, "");
                        String description = struct.getDescription();
                        if (!description.contains(INTERFACE_DESCRIPTION)) {
                            StringBuilder builder = new StringBuilder(INTERFACE_DESCRIPTION);
                            builder.append(fieldName);
                            struct.setDescription(builder.toString());
                        } else if (!description.contains(fieldName)) {
                            StringBuilder builder = new StringBuilder(description);
                            builder.insert(
                                INTERFACE_DESCRIPTION.length(), fieldName+INTERFACE_SEPARATOR);
                            struct.setDescription(builder.toString());
                        }
                        replaceComponent(struct, parentBuilder.getSuperClassDataType(),
                            SUPER+parent.getName(), baseMap.get(parent));
                } else {
                    replaceComponent(struct, parentBuilder.getSuperClassDataType(),
                        SUPER+parent.getName(), baseMap.get(parent));
                }
            }
        } catch (InvalidDataTypeException e) {
            try {
                Msg.info(this, "Unable to resolve inheritance for "+type.getName());
            } catch (InvalidDataTypeException ex) {
                Msg.error(this, ERROR_MESSAGE);
            }
        }
        addVptr();
        fixComponents();
        return resolveStruct(struct);
    }

    protected void setSuperStructureCategoryPath(Structure parent)
        throws InvalidDataTypeException {
            try {
                parent.setCategoryPath(path);
                parent.setName(SUPER+parent.getName());
            } catch (InvalidNameException | DuplicateNameException e) {
                Msg.error(
                    this, "Failed to change placeholder struct "+type.getName()+"'s CategoryPath", e);
            }
    }

    protected Structure getSuperClassDataType() throws InvalidDataTypeException {
        DataTypeManager dtm = program.getDataTypeManager();
        DataTypePath dtPath = new DataTypePath(path, SUPER+type.getName());
        DataType dt = dtm.getDataType(dtPath);
        if (dt == null) {
            Structure superStruct = (Structure) getDataType().copy(dtm);
            setSuperStructureCategoryPath(superStruct);
            deleteVirtualComponents(superStruct);
            trimStructure(superStruct);
            return resolveStruct(superStruct);
        }
        return (Structure) dt;
    }

    protected static void clearComponent(Structure struct, int length, int offset) {
        if (offset >= struct.getLength()) {
            return;
        }
        for (int size = 0; size < length;) {
            DataTypeComponent comp = struct.getComponentAt(offset);
            if (comp!= null) {
                size += comp.getLength();
            } else {
                size++;
            }
            struct.deleteAtOffset(offset);
        }
    }

    protected static void replaceComponent(Structure struct, DataType parent,
        String name, int offset) {
            clearComponent(struct, parent.getLength(), offset);
            struct.insertAtOffset(offset, parent, parent.getLength(), name, null);
    }

    protected abstract void addVptr();

    protected static void trimStructure(Structure struct) {
        DataTypeComponent[] comps = struct.getDefinedComponents();
        if (comps.length == 0) {
            return;
        }
        int endOffset =  comps[comps.length-1].getEndOffset()+1;
        while (struct.getLength() > endOffset) {
            struct.deleteAtOffset(endOffset);
        }
    }

    protected static Structure resolveStruct(Structure struct) {
        DataTypeManager dtm = struct.getDataTypeManager();
        return (Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    protected void deleteVirtualComponents(Structure superStruct) throws InvalidDataTypeException {
        Set<Structure> parents = new HashSet<>();
        for (ClassTypeInfo parent : type.getVirtualParents()) {
            Structure parentStruct = getParentBuilder(parent).getSuperClassDataType();
            parents.add(parentStruct);
            parents.add(parent.getClassDataType());
        }
        DataTypeComponent[] comps = superStruct.getDefinedComponents();
        for (DataTypeComponent comp : comps) {
            DataType dt = comp.getDataType();
            if (parents.contains(dt)) {
                int ordinal = comp.getOrdinal();
                int numComponents = superStruct.getNumComponents() - 1;
                int[] ordinals = IntStream.rangeClosed(ordinal, numComponents).toArray();
                superStruct.delete(ordinals);
                break;
            }
        }
    }

    private boolean validFieldName(String name) {
        if (name == null) {
            return true;
        }
        return !name.startsWith(SUPER) && !name.equals("_vptr");
    }

    private void stashComponents() {
        if(dtComps.isEmpty()) {
            dtComps = new HashMap<>(struct.getNumDefinedComponents());
            for (DataTypeComponent comp : struct.getDefinedComponents()) {
                String fieldName = comp.getFieldName();
                if (validFieldName(fieldName)) {
                    if (!comp.getDataType().isNotYetDefined()) {
                        CompositeDataTypeElementInfo savedComp = new CompositeDataTypeElementInfo(
                            comp.getDataType(), comp.getOffset(),
                            comp.getLength(), comp.getDataType().getAlignment());
                        dtComps.put(savedComp, comp.getFieldName());
                    }
                }
            }
            struct.deleteAll();
        }
    }

    private void fixComponents() {
        for (CompositeDataTypeElementInfo comp : dtComps.keySet()) {
            int offset = comp.getDataTypeOffset();
            DataTypeComponent replaced = struct.getComponentAt(offset);
            if (replaced != null && !validFieldName(replaced.getFieldName())) {
                continue;
            }
            replaceComponent(struct, (DataType) comp.getDataTypeHandle(),
                             dtComps.get(comp), offset);
        }
    }
}
