#@category CppClassAnalyzer
import json
from ghidra.app.cmd.data.rtti.gcc import VtableModel
from ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory import getTypeInfo, isTypeInfo
from ghidra.app.cmd.data.rtti.TypeInfo import SYMBOL_NAME
from ghidra.app.cmd.data.rtti import ClassTypeInfo
from ghidra.program.model.data import InvalidDataTypeException
from ghidra.program.model.data.DataTypeConflictHandler import REPLACE_HANDLER
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import FileDataTypeManager
from ghidra.app.cmd.data.rtti.gcc.GnuUtils import isGnuCompiler
from ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin.windows.WindowsCppClassAnalyzer import getClassTypeInfoList

mangled_prefix = "_Z"
mangled_vs = '??'

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
        if mangled_prefix in symbol_name or '@' in symbol_name:
            return symbol_name

def get_types(symbol_table):
    if not isGnuCompiler(currentProgram):
        return getClassTypeInfoList(currentProgram)
    type_symbols = [symbol for symbol in symbol_table.getAllSymbols(False)
                    if SYMBOL_NAME in symbol.getName()]
    types = []
    for symbol in type_symbols:
        if validate_typeinfo(symbol):
            ti = getTypeInfo(currentProgram, symbol.getAddress())
            if isinstance(ti, ClassTypeInfo):
                types.append(ti)
    return types

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
    return ti.getVtable() != VtableModel.NO_VTABLE

def populate_database(symbol_table, vtables):
    db = {}
    monitor.setMessage("dumping vtables")
    monitor.initialize(len(vtables))
    for vtable in vtables:
        key = vtable.getTypeInfo().getUniqueTypeName()
        if key in db:
            gc = vtable.getTypeInfo().getGhidraClass()
            vtable_symbols = symbol_table.getSymbols('vtable', gc)
            assert len(vtable_symbols) <= 1, "Key not unique! "+gc.getName(True)
        value = get_function_symbols(symbol_table, vtable)
        db[key] = value
        monitor.incrementProgress(1)
    return db

if __name__ == '__main__':
    file = FileDataTypeManager.convertFilename(askFile("Select New Archive File", "OK"))
    dtm = FileDataTypeManager.createFileArchive(file)
    if dtm.isClosed():
        dtm = FileDataTypeManager.openFileArchive(file, True)
    symbol_table = currentProgram.getSymbolTable()
    types = get_types(symbol_table)
    monitor.initialize(len(types))
    monitor.setMessage("finding vtables")
    vtables = [ti.getVtable() for ti in types if validate_vtable(ti)]
    vtable_database = populate_database(symbol_table, vtables)
    with open(askFile('chose output file', 'OK').toString(), 'w+') as fd:
        json.dump(vtable_database, fd, indent=4)
    transaction = dtm.startTransaction("Adding Classes")
    print(len(types))
    for ti in types:
        try:
            dtm.addDataType(ti.getClassDataType(), REPLACE_HANDLER)
        except:
            pass
    dtm.endTransaction(transaction, True)
    dtm.save()
    dtm.close()
