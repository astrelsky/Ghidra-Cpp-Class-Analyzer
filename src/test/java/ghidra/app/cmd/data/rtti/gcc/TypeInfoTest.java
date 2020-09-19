package ghidra.app.cmd.data.rtti.gcc;

import java.util.function.Predicate;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.FundamentalTypeInfoModel;

import org.junit.Test;

public class TypeInfoTest extends X86GccRttiTest {

	private static void validate(TypeInfo type) {
		assert type.getDataType() != null :
			String.format("%s of type %s at %s is not valid",
				type.getName(), type.getAddress(), type.getClass().getSimpleName());
	}

	@Test
	public void validationTest() throws Exception {
		initialize();
		builder.getTypeInfoStream()
			.filter(Predicate.not(FundamentalTypeInfoModel.class::isInstance))
			.forEach(TypeInfoTest::validate);
	}
}
