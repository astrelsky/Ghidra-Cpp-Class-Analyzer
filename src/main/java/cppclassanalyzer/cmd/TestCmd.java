package cppclassanalyzer.cmd;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

public class TestCmd extends BackgroundCommand {

	private Address address;
	private Program program;
	private DataType dt;

	public TestCmd(Address address) {
		this.address = address;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if (!(obj instanceof Program)) {
			setStatusMsg("Can only be applied to a program");
			return false;
		}
		this.program = (Program) obj;
		this.dt = IntegerDataType.dataType.clone(program.getDataTypeManager());
		createDt(1, true);
		createDt(2, false);
		createDt(3, true);
		return true;
	}

	private void createDt(int num, boolean success) {
		Listing listing = program.getListing();
		listing.clearCodeUnits(address, address.add(dt.getLength()), true);
		int id = program.startTransaction("create dt "+Integer.toString(num));
		try {
			listing.createData(address, dt);
		} catch (CodeUnitInsertionException e) {
			throw new AssertException(e);
		} finally {
			program.endTransaction(id, success);
		}
		address = address.add(dt.getLength());
	}

}