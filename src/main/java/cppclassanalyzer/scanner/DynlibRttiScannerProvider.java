package cppclassanalyzer.scanner;

import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.listing.Program;

public final class DynlibRttiScannerProvider implements RttiScannerProvider {

	@Override
	public boolean canScan(Program program) {
		if (program.getExecutableFormat().equals(MachoLoader.MACH_O_NAME)) {
			return GnuUtils.isGnuCompiler(program);
		}
		return false;
	}

	@Override
	public RttiScanner getScanner(Program program) {
		return new DynlibRttiScanner(program);
	}
	
}
