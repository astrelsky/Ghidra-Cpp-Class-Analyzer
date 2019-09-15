#@category VtableDatabase
import json
from ghidra.app.cmd.data.rtti.gcc import VtableModel
from ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory import getTypeInfo, isTypeInfo
from ghidra.app.cmd.data.rtti.TypeInfo import SYMBOL_NAME

mangled_prefix = "_Z"

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

if __name__ == '__main__':
    symbol_table = currentProgram.getSymbolTable()
    types = get_types(symbol_table)
    monitor.initialize(len(types))
    monitor.setMessage("finding vtables")
    vtables = [ti.getVtable() for ti in types if validate_vtable(ti)]
    vtable_database = populate_database(symbol_table, vtables)
    with open(askFile('chose output file', 'vtable_database.json').toString(), 'w+') as fd:
        json.dump(vtable_database, fd, indent=4)
