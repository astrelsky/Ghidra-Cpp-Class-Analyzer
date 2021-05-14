package ghidra.app.cmd.data.rtti.gcc.factory;

import cppclassanalyzer.data.TypeInfoManager;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FactoryStructureDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.docking.settings.Settings;

public class TypeInfoFactoryDataType extends FactoryStructureDataType {

	private static final String DATA_TYPE_NAME = "TypeInfo";
	private static final String DESCRIPTION =
		"Automatically applies the correct typeinfo structure upon creation";

	public TypeInfoFactoryDataType() {
		this(null);
	}

	public TypeInfoFactoryDataType(DataTypeManager dtm) {
		super(DATA_TYPE_NAME, dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return DATA_TYPE_NAME;
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		if (dtm instanceof BuiltInDataTypeManager) {
			return new TypeInfoFactoryDataType(dtm);
		}
		// stay in the builtin datatype manager
		return this;
	}

	@Override
	protected void populateDynamicStructure(MemBuffer buf, Structure struct) {}

	public static DataType getDataType(Program program, Address address) {
		TypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
		TypeInfo typeinfo = manager.getTypeInfo(address);
		return typeinfo != null ? typeinfo.getDataType() : null;
	}

	@Override
	public DataType getDataType(MemBuffer buf) {
		return getDataType(buf.getMemory().getProgram(), buf.getAddress());
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}
}
