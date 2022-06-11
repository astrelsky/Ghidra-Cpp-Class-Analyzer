package cppclassanalyzer.scanner;

import java.util.List;
import java.util.Set;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface RttiScanner {

	/**
	 * Scan the program for the ClassTypeInfo's
	 * @param log the log to use for logging errors
	 * @param monitor the task monitor
	 * @return true if the scan was successful
	 * @throws CancelledException if the scan is cancelled
	 */
	public boolean scan(MessageLog log, TaskMonitor monitor) throws CancelledException;

	/**
	 * Scans the program for Fundamental TypeInfo's
	 * @param log the log to use for logging errors
	 * @param monitor the task monitor
	 * @return the addresses of the fundamental type info's
	 * @throws CancelledException if the scan is cancelled
	 */
	public Set<Address> scanFundamentals(MessageLog log, TaskMonitor monitor) throws CancelledException;

	public static RttiScanner getScanner(Program program) {
		List<RttiScannerProvider> providers =
			ClassSearcher.getInstances(RttiScannerProvider.class);
		providers.add(DynlibRttiScannerProvider.INSTANCE);
		providers.add(ItaniumAbiRttiScannerProvider.INSTANCE);
		for (RttiScannerProvider scanner : providers) {
			if (scanner.canScan(program)) {
				return scanner.getScanner(program);
			}
		}
		return null;
	}

}
