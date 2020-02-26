#@category CppClassAnalyzer
import json
from ghidra.util.task.TaskMonitor import DUMMY
from ghidra.program.model.data import InvalidDataTypeException
from ghidra.app.cmd.data.rtti.gcc import VtableModel
from ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils import getDataTypePath
from ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils import getVptrDataType
from ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory import getTypeInfo, isTypeInfo
from ghidra.app.cmd.data.rtti.TypeInfo import SYMBOL_NAME
from ghidra.app.util.demangler.DemanglerUtil import demangle
from ghidra.app.util.demangler import DemanglerOptions
from ghidra.program.model.symbol.SourceType import IMPORTED
from ghidra.util.exception import CancelledException
from ghidra.app.cmd.data.rtti import ClassTypeInfo
from ghidra.program.model.data import DataTypePath
from ghidra.program.model.data import Composite, FunctionDefinition, Union, Structure, Array, Pointer
from ghidra.program.model.data import UnionDataType, StructureDataType

mangled_prefix = "_Z"
options = DemanglerOptions()
global dInterface
mangled_symbols = []

def get_function_symbols(table, vtable):
    result = []
    function_tables = vtable.getFunctionTables()
    for function_table in function_tables:
        symbol_list = []
        for function in function_table:
            if function:
                mangled = get_mangled_symbol(table, function.getEntryPoint())
                if mangled:
                    symbol_list.append(mangled)
            else:
                symbol_list.append("")
        result.append(symbol_list)
    return result

def get_mangled_symbol(table, address):
    symbols = table.getSymbols(address)
    for symbol in symbols:
        symbol_name = symbol.getName()
        if mangled_prefix in symbol_name:
            return symbol_name

def get_types(symbol_table):
    type_symbols = [symbol for symbol in symbol_table.getAllSymbols(False)
                    if SYMBOL_NAME in symbol.getName()]
    return [getTypeInfo(currentProgram, symbol.getAddress()) for symbol in type_symbols
            if validate_typeinfo(symbol)]

def monitored(function):
    def wrapper(arg):
        result = function(arg)
        monitor.incrementProgress(1)
        return result
    return wrapper

@monitored
def validate_typeinfo(symbol):
    return isTypeInfo(currentProgram, symbol.getAddress())

@monitored
def validate_vtable(ti):
    if not isinstance(ti, ClassTypeInfo):
        return False
    return ti.getVtable() != VtableModel.NO_VTABLE

def populate_database(symbol_table, vtables):
    db = {}
    monitor.initialize(len(vtables))
    monitor.setMessage("dumping vtables")
    for vtable in vtables:
        key = vtable.getTypeInfo().getUniqueTypeName()
        assert key not in db, "Key not unique!"
        value = get_function_symbols(symbol_table, vtable)
        db[key] = value
        monitor.incrementProgress(1)
    return db

def apply_function_definition(mangled, function):
    if mangled:
        table = currentProgram.getSymbolTable()
        s = table.createLabel(function.getEntryPoint(), mangled, IMPORTED)

def apply_db_definitions(vtables, db):
    monitor.initialize(len(vtables))
    monitor.setMessage("Applying vtable definitions")
    count = 0
    for vtable in vtables:
        key = vtable.getTypeInfo().getUniqueTypeName()
        if key in db:
            value = db[key]
            for mangled_table, function_table in zip(value, vtable.getFunctionTables()):
                for mangled, function in zip(mangled_table, function_table):
                    if function:
                        apply_function_definition(mangled, function)
                        count += 1
        monitor.incrementProgress(1)
    return count

def get_datatype_path(entry):
    return DataTypePath(entry["CategoryPath", "Name"])

def get_datatype(entry):
    global dt_table
    path = get_datatype_path(entry)
    dtm = currentProgram.getDataTypeManager()
    dt = dtm.getDataType(path)
    if dt:
        return dt
    return dt_table[entry["Type"]](entry)

def get_pointer(entry):
    base = get_datatype(entry["BaseType"])
    dtm = currentProgram.getDataTypeManager()
    return dtm.getPointer(base, entry["length"])

def get_array(entry):
    base = get_datatype(entry["BaseType"])
    dtm = currentProgram.getDataTypeManager()
    return ArrayDataType(base, entry["length"], entry["element_length"])

def get_structure(entry):
    path = get_datatype_path(entry).getCategoryPath()
    dtm = currentProgram.getDataTypeManager()
    struct = StructureDataType(path, entry["Name"], 0, dtm)
    for comp in entry["Components"]:
        if comp["bitfield"]:
            bitfield = comp["bitfield"]
            struct.insertBitfieldAt(comp["offset"], bitfield["byteWidth"],
                                    bitfield["bitOffset"], get_datatype(bitfield["DataType"]),
                                    bitfield["bitSize"], comp["name"], comp["comment"])
        else:
            struct.insertAtOffset(
                comp["offset"], get_datatype(comp["DataType"]),
                comp["length"], comp["name"], comp["comment"])

def get_union(entry):
    path = get_datatype_path(entry).getCategoryPath()
    dtm = currentProgram.getDataTypeManager()
    union = UnionDataType(path, entry["Name"], dtm)
    for comp in entry["Components"]:
        if comp["bitfield"]:
            bitfield = comp["bitfield"]
            union.addBitField(get_datatype(bitfield["DataType"]), bitfield["bitSize"],
                              comp["name"], comp["comment"])
        else:
            union.add(get_datatype(comp["DataType"]), comp["length"], comp["name"], comp["comment"])

if __name__ == '__main__':
    symbol_table = currentProgram.getSymbolTable()
    types = get_types(symbol_table)
    monitor.initialize(len(types))
    monitor.setMessage("finding vtables")
    vtables = [ti.getVtable() for ti in types if validate_vtable(ti)]
    db = {}
    while True:
        try:
            with open(askFile('chose database file', 'open').toString(), 'r') as fd:
                db = json.load(fd)
            applied_definitions = apply_db_definitions(vtables, db)
            print('Successfully applied %d function definitions' % applied_definitions)
        except CancelledException:
            for symbol in mangled_symbols:
                for s in symbol_table.getSymbols(symbol.getAddress()):
                    if not s.isPrimary():
                        s.delete()
                demangled = demangle(s.getName)
                if demangled:
                    address = symbol.getAddress()
                    removeFunction(getFunctionAt(address))
                    demangled.applyTo(currentProgram, address, options, DUMMY)
            break
