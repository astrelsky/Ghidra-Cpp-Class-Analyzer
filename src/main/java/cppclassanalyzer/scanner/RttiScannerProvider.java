package cppclassanalyzer.scanner;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

public interface RttiScannerProvider extends ExtensionPoint {

	public boolean canScan(Program program);

	public RttiScanner getScanner(Program program);
}
