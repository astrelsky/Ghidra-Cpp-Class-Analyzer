package cppclassanalyzer.vs;

import java.util.Map;

import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.Vptr;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;

public class VsCppClassBuilder extends AbstractCppClassBuilder {

	private static final String VFPTR = "vfptr";
	private static final String VBPTR = "vbptr";
	private int currOffset = 0;

	public VsCppClassBuilder(VsClassTypeInfo type) {
		super(type);
	}

	protected void addVptrs(Structure struct, int offset) {
		currOffset = 0;
		addVfptr(struct, offset);
		if (!getType().getVirtualParents().isEmpty()) {
			addVbptr(struct);
		}
	}

	private void addVfptr(Structure struct, int offset) {
		Vptr[] vptrs = getVptrs();
		if (vptrs == null)
			return;

		for (int i = 0; i < vptrs.length; i++) {
			Program program = getProgram();
			Address vftableAddr = vptrs[i].getTableAddr();
			Address objLocatorAddr = TypeInfoUtils.getAbsoluteAddress(program,
					vftableAddr.subtract(pointerSize()));
			try {
				MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(),
						objLocatorAddr.add(pointerSize()));
				int vftableOffset = buf.getInt(0);
				if (offset == vftableOffset) {
					replaceComponent(struct, vptrs[i].getDataType(), VFPTR, 0);
					this.currOffset += pointerSize();
					return;
				}
			} catch (MemoryAccessException e) {
				Msg.error(this, e);
			}
		}
	}

	/**  {@link Rtti4Model#getVbTableOffset} */
	private void addVbptr(Structure struct) {
		Program program = getProgram();
		DataType vbptr = program.getDataTypeManager().getPointer(
			MSDataTypeUtils.getPointerDisplacementDataType(program), pointerSize());
		replaceComponent(struct, vbptr, VBPTR, currOffset);
	}

	@Override
	protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
		return getType().getBaseOffsets();
	}

	@Override
	protected VsClassTypeInfo getType() {
		return (VsClassTypeInfo) super.getType();
	}

	@Override
	protected boolean invalidFieldName(String name) {
		if (name == null) {
			return true;
		}
		return !name.startsWith(SUPER) && !name.contains(VFPTR) &&
				!name.contains(VBPTR);
	}
}
