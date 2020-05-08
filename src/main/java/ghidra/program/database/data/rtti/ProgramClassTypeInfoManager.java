package ghidra.program.database.data.rtti;

import java.util.stream.Stream;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.program.database.data.rtti.typeinfo.ArchivedClassTypeInfo;
import ghidra.program.database.data.rtti.vtable.ArchivedGnuVtable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Manager for {@link ClassTypeInfo}
 */
public interface ProgramClassTypeInfoManager extends TypeInfoManager, ClassTypeInfoManager {

	Program getProgram();
	ClassTypeInfo getType(Address address) throws UnresolvedClassTypeInfoException;
	ClassTypeInfo resolve(ClassTypeInfo type);
	Vtable resolve(Vtable vtable);
	default Iterable<ClassTypeInfo> getTypes() {
		return getTypes(false);
	}
	Iterable<ClassTypeInfo> getTypes(boolean reverse);
	default Iterable<Vtable> getVtables() {
		return getVtableIterable(false);
	}
	Iterable<Vtable> getVtableIterable(boolean reverse);
	int getVtableCount();
	default Stream<ClassTypeInfo> getTypeStream() {
		return getTypeStream(false);
	}
	Stream<ClassTypeInfo> getTypeStream(boolean reverse);
	Stream<Vtable> getVtableStream();
	ClassTypeInfo getExternalClassTypeInfo(Address address);

	void findVtables(TaskMonitor monitor) throws CancelledException;

	ClassTypeInfo resolve(ArchivedClassTypeInfo type);
	Vtable resolve(ArchivedGnuVtable vtable);

}