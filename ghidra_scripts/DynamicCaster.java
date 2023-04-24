/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Andrew J. Strelsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
// Finds all calls to __dynamic_cast, determines the source and destination data types from the
// __class_type_info parameters and then generated a function signature override. This is extremely
// useful as it assists the decompiler's type propogation algorithm which cannot handle virtual classes.
//@category CppClassAnalyzer
//@author Andrew J. Strelsky
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.decompiler.function.HighFunctionCall;
import cppclassanalyzer.decompiler.function.HighFunctionCallParameter;
import cppclassanalyzer.script.CppClassAnalyzerGhidraScript;

public class DynamicCaster extends CppClassAnalyzerGhidraScript {

	private static final String FORMAL_SIGNATURE =
		"void * __dynamic_cast(void * src_ptr, __class_type_info * src_type, "
		+"__class_type_info * dst_type, ptrdiff_t src2dst)";
	private static final String DYNAMIC_CAST = "__dynamic_cast";
	private static final String TMP_NAME = "tmpname";
	private static final String NAME_ROOT = "prt";
	private static final String AUTO_CAT = "/auto_proto";

	private SymbolTable table;
	private DataTypeManager dtm;
	private FunctionSignature sig;
	private DecompilerAPI api;
	private Function dynamicCast;

	@Override
	public void run() throws Exception {
		api = getService().getDecompilerAPI(currentProgram);
		api.setMonitor(monitor);
		table = currentProgram.getSymbolTable();
		dtm = currentProgram.getDataTypeManager();
		dynamicCast = getDynamicCast();
		if (dynamicCast == null) {
			return;
		}
		if (!dynamicCast.getPrototypeString(true, false).equals(FORMAL_SIGNATURE)) {
			printerr("The function at "+dynamicCast.getEntryPoint().toString()
					 +" doesnt match the cxxabi defined functions signature:\n"
					 +FORMAL_SIGNATURE);
			return;
		}
		sig = dynamicCast.getSignature();
		List<Function> functions =
			Arrays.stream(getReferencesTo(dynamicCast.getEntryPoint()))
			  .filter(DynamicCaster::isCall)
			  .map(Reference::getFromAddress)
			  .map(this::getFunctionContaining)
			  .filter(Objects::nonNull)
			  .distinct()
			  .collect(Collectors.toList());
		monitor.initialize(functions.size());
		monitor.setMessage("Analyzing __dynamic_cast calls");
		for (Function function : functions) {
			monitor.checkCancelled();
			doDynamicCast(function);
			monitor.incrementProgress(1);
		}
	}

	private Function getDynamicCast() {
		List<Function> functions = getGlobalFunctions(DYNAMIC_CAST);
		if (functions.size() > 1) {
			printerr("More than one __dynamic_cast function found.");
			return null;
		}
		if (functions.isEmpty()) {
			printerr("__dynamic_cast function not found");
			return null;
		}
		return functions.get(0);
	}

	private static boolean isCall(Reference r) {
		RefType type = r.getReferenceType();
		if (type.isCall()) {
			return !(type.isComputed() || type.isIndirect());
		}
		return false;
	}

	private void doDynamicCast(Function function) throws Exception {
		List<HighFunctionCall> calls = api.getFunctionCalls(function)
			.stream()
			.filter(f -> f.getFunction().equals(dynamicCast))
			.collect(Collectors.toList());
		for (HighFunctionCall call : calls) {
			monitor.checkCancelled();
			List<HighFunctionCallParameter> params = call.getParameters();
			Symbol srcSymbol = getSymbol(params.get(1));
			Symbol destSymbol = getSymbol(params.get(2));
			if (srcSymbol == null || destSymbol == null) {
				continue;
			}
			ClassTypeInfo srcType = currentManager.getType(srcSymbol.getAddress());
			ClassTypeInfo destType = currentManager.getType(destSymbol.getAddress());
			if (srcType != null && destType != null) {
				overrideFunction(function, call.getAddress(), srcType, destType);
			}
		}
	}

	private Symbol getSymbol(HighFunctionCallParameter param) {
		Varnode v = param.getVariableToken().getPcodeOp().getInput(1);
		if (v != null) {
			return v.getHigh()
				.getSymbol()
				.getSymbol();
		}
		return null;
	}

	private static ParameterDefinition getParameter(DataType dataType) {
		DataType dt = PointerDataType.getPointer(dataType, -1);
		return new ParameterDefinitionImpl(null, dt, null);
	}

	private FunctionDefinition getFunctionSignature(ClassTypeInfo src, ClassTypeInfo dest,
			Function function)throws Exception {
		FunctionDefinition def = new FunctionDefinitionDataType(sig);
		ParameterDefinition[] params = def.getArguments();
		params[0] = getParameter(src.getClassDataType());
		params[1] = getParameter(src.getDataType());
		params[2] = getParameter(dest.getDataType());
		def.setName(TMP_NAME);
		def.setArguments(params);
		def.setReturnType(dtm.getPointer(dest.getClassDataType()));
		return def;
	}

	private void overrideFunction(Function function, Address address,
			ClassTypeInfo src, ClassTypeInfo dest) throws Exception {
		FunctionDefinition def = getFunctionSignature(src, dest, function);
		if (def != null) {
			DataTypeSymbol symbol = new DataTypeSymbol(def, NAME_ROOT, AUTO_CAT);
			Namespace space = HighFunction.findCreateOverrideSpace(function);
			if (space != null) {
				try {
					symbol.writeSymbol(table, address, space, dtm, true);
				} catch (InvalidInputException e) {
					// already overridden
				}
			}
		}
	}
}
