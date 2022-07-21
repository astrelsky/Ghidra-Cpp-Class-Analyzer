package ghidra.app.cmd.data.rtti.gcc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

import org.junit.Test;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import generic.json.JSONParser;
import generic.json.JSONToken;
import resources.ResourceManager;

public final class ClassBuilderTest extends X86GccRttiTest {

    private static final String SERIALIZED_FILE = "cpp_classes.json";

    private static String getSerializedData() throws IOException {
        try (InputStream stream = ResourceManager.getResourceAsStream(SERIALIZED_FILE)) {
            InputStreamReader streamReader = new InputStreamReader(stream);
            BufferedReader reader = new BufferedReader(streamReader);
            return reader.lines().collect(Collectors.joining());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<SerializedNamespace> parseData() throws Exception {
        String data = getSerializedData();
        JSONParser parser = new JSONParser();
        LinkedList<JSONToken> tokens = new LinkedList<>();
        switch (parser.parse(data.toCharArray(), tokens)) {
            case JSMN_ERROR_INVAL:
                throw new Exception("JSON contains invalid character");
            case JSMN_ERROR_NOMEM:
                throw new Exception("Not enough tokens");
            case JSMN_ERROR_PART:
                throw new Exception("Malformed or missing JSON data");
            case JSMN_SUCCESS:
                break;
        }
        Map<String, Object> namespaces =
            (Map<String, Object>) parser.convert(data.toCharArray(), tokens);
        return namespaces.entrySet()
                .stream()
                .map(SerializedNamespace::new)
                .collect(Collectors.toList());
    }

    @Test
    public void test() throws Exception {
        initialize();
        ProgramClassTypeInfoManager manager = getManager();
        List<SerializedNamespace> namespaces = parseData();
        runGccRttiAnalyzer(program);
        runClassAnalyzer(program);
        for (SerializedNamespace sns : namespaces) {
            for (SerializedClass clazz : sns.getClasses()) {
                Namespace ns = NamespaceUtils.getNonFunctionNamespace(program, clazz.getPath());
                assert ns instanceof GhidraClass;
                ClassTypeInfo type = manager.getType((GhidraClass) ns);
                clazz.assertEquivalent(type);
            }
        }
    }
	
	@Test
	public void vtableStructureTest() throws Exception {
		initialize();
		ProgramClassTypeInfoManager manager = getManager();
        runGccRttiAnalyzer(program);
        runClassAnalyzer(program);
		for (Vtable vtable : manager.getVtables()) {
            Function[][] table = vtable.getFunctionTables();
			if (table.length == 0 || table[0].length == 0) {
				continue;
			}
			ClassTypeInfo type = vtable.getTypeInfo();
			Pointer ptr = (Pointer) ClassTypeInfoUtils.getVptrDataType(program, type);
			Structure struct = (Structure) ptr.getDataType();
			assert struct.getNumComponents() > 0 : struct.getDataTypePath().toString() + " is empty";
		}
	}

    private static class SerializedNamespace {

        private final String name;
        private final List<SerializedClass> classes;

        @SuppressWarnings("unchecked")
        SerializedNamespace(Map.Entry<String, Object> data) {
            this.name = data.getKey();
            Map<String, Object> classData = (Map<String, Object>) data.getValue();
            SymbolPath path = new SymbolPath(name);
            this.classes = classData.entrySet()
                    .stream()
                    .map(e -> new SerializedClass(path, e))
                    .collect(Collectors.toUnmodifiableList());
        }

        List<SerializedClass> getClasses() {
            return classes;
        }
    }

    private static class SerializedClass {

        private final SymbolPath path;
        private final List<SerializedClassMember> members;

        @SuppressWarnings("unchecked")
        SerializedClass(SymbolPath parent, Map.Entry<String, Object> data) {
            this.path = new SymbolPath(parent, data.getKey());
            Object value = data.getValue();
            if (value == null) {
                this.members = Collections.emptyList();
            } else {
                Map<String, Object> classData = (Map<String, Object>) value;
                if (classData.containsKey("offsets")) {
                    Map<String, String> memberData =
                        (Map<String, String>) classData.get("offsets");
                    this.members = memberData.entrySet()
                            .stream()
                            .map(SerializedClassMember::new)
                            .collect(Collectors.toUnmodifiableList());
                } else {
                    this.members = Collections.emptyList();
                }
            }
        }

        SymbolPath getPath() {
            return path;
        }

        void assertEquivalent(ClassTypeInfo type) throws Exception {
            String name = type.getGhidraClass().getName(true);
            Structure struct = type.getClassDataType();
            for (SerializedClassMember member : members) {
                if (!member.getFieldName().startsWith("super_")) {
                    // only the super classes would be defined
                    continue;
                }
                DataTypeComponent comp = struct.getComponentAt(member.getOffset());
                assert comp != null
                        : String.format("%s is missing %s at offset %d\n%s",
                            name, member.getFieldName(), member.getOffset(), struct);
                String fieldName = comp.getFieldName();
                assert fieldName != null && fieldName.equals(member.getFieldName())
                        : String.format(
                            "%s at offset %d does not match the expected member %s in %s\n%s",
                            fieldName, member.getOffset(), member.getFieldName(), name, struct);
            }
        }

        @Override
        public String toString() {
            return path.toString();
        }
    }

    private static class SerializedClassMember {

        private final int offset;
        private final String name;

        SerializedClassMember(Map.Entry<String, String> data) {
            this.name = data.getKey();
            this.offset = Integer.parseInt(data.getValue());
        }

        String getFieldName() {
            return name;
        }

        int getOffset() {
            return offset;
        }

        @Override
        public String toString() {
            return name;
        }

    }

    
}
