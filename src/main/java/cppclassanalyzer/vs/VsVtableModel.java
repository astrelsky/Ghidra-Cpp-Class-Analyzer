package cppclassanalyzer.vs;

import java.util.List;
import java.util.ArrayList;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import static ghidra.program.model.data.Undefined.isUndefined;

public class VsVtableModel implements Vtable {

	public static final String PURE_VIRTUAL_FUNCTION_NAME = "_purecall";

	private final Program program;
	private final List<VfTableModel> vftables;
	private final ClassTypeInfo type;
	private final MemBuffer vbtableBuffer;

	private static final DataValidationOptions DEFAULT_OPTIONS = new DataValidationOptions();

	public VsVtableModel(Program program, List<Address> addresses, RttiModelWrapper type) {
		this.program = program;
		this.vftables = new ArrayList<>(addresses.size());
		this.type = type;
		for (Address address : addresses) {
			vftables.add(new VfTableModel(program, address, DEFAULT_OPTIONS));
		}
		this.vbtableBuffer = getVbtableBuffer();
	}

	private MemBuffer getVbtableBuffer() {
		if (vftables.isEmpty()) {
			return null;
		}
		VfTableModel vtable = vftables.get(vftables.size() - 1);
		Array array = (Array) vtable.getDataType();
		if (array == null) {
			return null;
		}
		final Address addr = vtable.getAddress().add(array.getLength()+array.getElementLength());
		return new MemoryBufferImpl(program.getMemory(), addr);
	}

	@Override
	public ClassTypeInfo getTypeInfo() {
		return type;
	}

	@Override
	public Address[] getTableAddresses() {
		Address[] addresses = new Address[vftables.size()];
		for (int i = 0; i < addresses.length; i++) {
			addresses[i] = vftables.get(i).getAddress();
		}
		return addresses;
	}

	private Function[] getFunctions(VfTableModel vftable) {
		List<Function> functions = new ArrayList<>(vftable.getElementCount());
		FunctionManager manager = program.getFunctionManager();
		for (int i = 0; i < vftable.getElementCount(); i++) {
			Function f = manager.getFunctionAt(vftable.getVirtualFunctionPointer(i));
			if (f == null) {
				break;
			}
			functions.add(f);
		}
		return functions.toArray(Function[]::new);
	}

	@Override
	public Function[][] getFunctionTables() {
		List<Function[]> tables = new ArrayList<>(vftables.size());
		for (VfTableModel vftable : vftables) {
			tables.add(getFunctions(vftable));
		}
		return tables.toArray(new Function[tables.size()][]);
	}

	protected List<VfTableModel> getVfTables() {
		return vftables;
	}

	@Override
	public boolean containsFunction(Function function) {
		for (Function[] functionTables : getFunctionTables()) {
			for (Function vFunction : functionTables) {
				if (vFunction.equals(function)) {
					return true;
				}
			}
		}
		return false;
	}

	public int getVirtualOffset(Rtti1Model model) throws InvalidDataTypeException {
		if (vbtableBuffer != null) {
			try {
				final int offset = model.getVDisp();
				final Address addr = vbtableBuffer.getAddress().add(offset);
				final Data data = program.getListing().getDataContaining(addr);
				if (data != null) {
					if (!isUndefined(data.getDataType()) && !(data.getValue() instanceof Scalar)) {
						return 0;
					}
				}
				return vbtableBuffer.getInt(offset);
			} catch (MemoryAccessException e) {
				Msg.error(this, e);
			}
		}
		return 0;
	}

	@Override
	public Address getAddress() {
		if (!vftables.isEmpty()) {
			return vftables.get(0).getAddress();
		}
		throw new AssertException("Ghidra-Cpp-Class-Analyzer: no vftables");
	}
}
