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
// Iterates through all vtable assignments and changes the assigned variable to
// the appropriate class datatype.
//@category CppClassAnalyzer
//@author Andrew J. Strelsky
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

import cppclassanalyzer.script.CppClassAnalyzerGhidraScript;

public class ClassReferences extends CppClassAnalyzerGhidraScript {

	private int count;

	@Override
	public void run() throws Exception {
		println("This script is currently in development and may not function properly");

		count = 0;
		List<Vtable> vftables = currentManager.getVtableStream()
			.collect(Collectors.toList());
		monitor.setMessage("Setting variable datatypes");
		monitor.initialize(vftables.size());
		for (Vtable vtable : vftables) {
			monitor.checkCancelled();
			processVtable(vtable);
			monitor.incrementProgress(1);
		}
		println("Created "+Integer.toString(count)+" class variable references.");
	}

	private void processVtable(Vtable vtable) throws Exception {
		Address vtableAddress = vtable.getTableAddresses()[0];
		ReferenceManager manager = currentProgram.getReferenceManager();
		for (Reference ref : manager.getReferencesTo(vtableAddress)) {
			monitor.checkCancelled();
			if (manager.getReferencedVariable(ref) != null) {
				Variable var = manager.getReferencedVariable(ref);
				if (!(var.getDataType() instanceof Structure)) {
					var.setDataType(vtable.getTypeInfo().getClassDataType(),
									true, true, SourceType.ANALYSIS);
					count++;
					continue;
				}
			}
			ReferenceProcessor processor = new ReferenceProcessor(vtable, ref);
			processor.process();
		}
	}

	private class ReferenceProcessor {

		private final Vtable vtable;
		private Instruction inst;
		private Function function;

		ReferenceProcessor(Vtable vtable, Reference ref) {
			this.vtable = vtable;
			Listing listing = currentProgram.getListing();
			this.inst = listing.getInstructionAt(ref.getFromAddress());
			if (inst != null) {			
				this.function = listing.getFunctionContaining(inst.getAddress());
			}
		}

		void process() throws Exception {
			if (inst == null || function == null) {
				return;
			}
			ReferenceManager manager = currentProgram.getReferenceManager();
			Reference[] refs = inst.getReferencesFrom();
			Variable var = Arrays.stream(refs)
				.map(manager::getReferencedVariable)
				.filter(Objects::nonNull)
				.findFirst()
				.orElse(null);
			if (var != null) {
				DataType dt = vtable.getTypeInfo().getClassDataType();
				DataType varDt = var.getDataType();
				if (varDt.isEquivalent(dt) || varDt.dependsOn(dt)) {
					return;
				}
				var.setDataType(dt, true, true, SourceType.ANALYSIS);
				Address addr = var.getMinAddress();
				if (addr != null) {
					String msg = String.format(
						"Set variable %s at %s to %s",
						var, inst.getAddress(), dt.getDataTypePath());
					println(msg);
				}
				count++;
				return;
			}
		}
	}
}
