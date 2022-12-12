package ghidra.app.cmd.data.rtti.gcc;

import java.util.Map;

import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import ghidra.program.model.address.Address;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils.Vptr;
import ghidra.program.model.data.Structure;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;

public class GccCppClassBuilder extends AbstractCppClassBuilder {

	public static final String VPTR = "vptr";

	public GccCppClassBuilder(ClassTypeInfo type) {
		super(type);
	}

	@Override
	protected void addVptrs(Structure struct, int offset) {
		Vptr[] vptrs = getVptrs();
		if (vptrs == null)
			return;

		for (int i = 0; i < vptrs.length; i++) {
			Address topOffsetAddr = vptrs[i].getTableAddr().subtract(2*pointerSize());
			MemoryBufferImpl buf = new MemoryBufferImpl(getProgram().getMemory(), topOffsetAddr);
			try {
				int topOffset = buf.getInt(0);
				if (offset == -topOffset) {
					replaceComponent(struct, vptrs[i].getDataType(), VPTR, 0);
					return;
				}
			} catch (MemoryAccessException e) {
				Msg.error(this, e);
			}
		}
	}

	@Override
	protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
		ClassTypeInfo type = getType();
		if (type instanceof AbstractClassTypeInfoDB) {
			return ((AbstractClassTypeInfoDB) type).getBaseOffsets();
		}
		return ClassTypeInfoUtils.getBaseOffsets(type);
	}

	@Override
	protected boolean invalidFieldName(String name) {
		if (name == null) {
			return true;
		}
		return !name.startsWith(SUPER) && !name.contains(VPTR);
	}
}
