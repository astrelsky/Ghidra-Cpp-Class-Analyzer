package ghidra.program.database.data.rtti;

import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Manager for {@link ClassTypeInfo}
 */
public interface ClassTypeInfoManager extends TypeInfoManager {
	
	static ClassTypeInfoManager getManager(Program program) {
		return (ClassTypeInfoManager) TypeInfoManager.getManager(program);
	}
	
	Program getProgram();
	ClassTypeInfo getClassTypeInfo(Address address);
	ClassTypeInfo getClassTypeInfo(GhidraClass gc);
	ClassTypeInfo getClassTypeInfo(Function fun);
	ClassTypeInfo getClassTypeInfo(String name);
	ClassTypeInfo getClassTypeInfo(String name, Namespace namespace);
	ClassTypeInfo resolve(ClassTypeInfo type);
	Vtable resolve(Vtable vtable);
	default Iterable<ClassTypeInfo> getIterable() {
		return getIterable(false);
	}
	Iterable<ClassTypeInfo> getIterable(boolean reverse);
	default Iterable<Vtable> getVtableIterable() {
		return getVtableIterable(false);
	}
	Iterable<Vtable> getVtableIterable(boolean reverse);
	int getClassTypeInfoCount();
	int getVtableCount();
	default Stream<ClassTypeInfo> getClassTypeInfoStream() {
		return getClassTypeInfoStream(false);
	}
	Stream<ClassTypeInfo> getClassTypeInfoStream(boolean reverse);
	Stream<Vtable> getVtableStream();
	
	void sort(TaskMonitor monitor) throws CancelledException;

}