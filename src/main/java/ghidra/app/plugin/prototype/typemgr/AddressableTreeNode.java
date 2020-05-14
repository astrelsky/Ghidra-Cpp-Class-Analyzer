package ghidra.app.plugin.prototype.typemgr;

import ghidra.program.model.address.Address;

public interface AddressableTreeNode {

	boolean hasAddress();
	Address getAddress();
}