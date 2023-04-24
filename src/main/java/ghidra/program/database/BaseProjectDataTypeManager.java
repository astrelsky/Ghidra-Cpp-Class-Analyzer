package ghidra.program.database;

import java.io.IOException;

import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import db.DBHandle;
import db.util.ErrorHandler;

public abstract class BaseProjectDataTypeManager extends ProjectDataTypeManager {
	
	public BaseProjectDataTypeManager(DataTypeArchiveDB dataTypeArchive, DBHandle handle, int openMode,
			ErrorHandler errHandler, Lock lock,
			TaskMonitor monitor) throws CancelledException, VersionException, IOException {
		super(dataTypeArchive, handle, openMode, errHandler, lock, monitor);
	}
}
