package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.FundamentalTypeInfoModel;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class TypeInfoTest extends AbstractGenericTest {

    @Test
    public void test() throws Exception {
        X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
        for (TypeInfo type : builder.getTypeInfoList()) {
            if (!(type instanceof FundamentalTypeInfoModel)) {
                // Invalid dynamic relocations prevent fundamentals from being valid
                assert type.isValid();
                assert type.getDataType() != null;
            }
        }
    }
}
