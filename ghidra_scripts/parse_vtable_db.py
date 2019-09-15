#@category VtableDatabase
import json
from ghidra.util.task.TaskMonitor import DUMMY
from ghidra.program.model.data import FunctionDefinition
from ghidra.program.model.data import InvalidDataTypeException
from ghidra.app.cmd.data.rtti.gcc import VtableModel
from ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils import getDataTypePath
from ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils import getVptrDataType
from ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory import getTypeInfo, isTypeInfo
from ghidra.app.cmd.data.rtti.TypeInfo import SYMBOL_NAME
from ghidra.app.util.demangler.DemanglerUtil import demangle
from ghidra.app.util.demangler import DemanglerOptions
from ghidra.program.model.symbol.SourceType import IMPORTED
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

mangled_prefix = "_Z"
options = DemanglerOptions()
global dInterface

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
    try:
        ti.getVtable().validate()
        return True
    except InvalidDataTypeException:
        return False

def fixupFunctionSignature(function):
    results = dInterface.decompileFunction(function, 0, None)
    prototype = results.getHighFunction().getFunctionPrototype()
    function.setReturnType(prototype.getReturnType(), IMPORTED)

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
    address = function.getEntryPoint()
    demangled = demangle(mangled)
    if demangled:
        removeFunction(function)
        demangled.applyTo(currentProgram, address, options, DUMMY)
        function = getFunctionAt(address)
        fixupFunctionSignature(function)

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


if __name__ == '__main__':
    decompiler = FlatDecompilerAPI(FlatProgramAPI(currentProgram))
    decompiler.initialize()
    dInterface = decompiler.getDecompiler()
    symbol_table = currentProgram.getSymbolTable()
    types = get_types(symbol_table)
    monitor.initialize(len(types))
    monitor.setMessage("finding vtables")
    vtables = [ti.getVtable() for ti in types if validate_vtable(ti)]
    db = {}
    with open(askFile('chose database file', 'open').toString(), 'r') as fd:
        db = json.load(fd)
    applied_definitions = apply_db_definitions(vtables, db)
    decompiler.dispose()
    print('Successfully applied %d function definitions' % applied_definitions)
