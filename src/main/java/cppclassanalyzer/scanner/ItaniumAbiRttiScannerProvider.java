package cppclassanalyzer.scanner;

import ghidra.app.cmd.data.rtti.gcc.GnuUtils;
import ghidra.program.model.listing.Program;

public final class ItaniumAbiRttiScannerProvider implements RttiScannerProvider {

	@Override
	public boolean canScan(Program program) {
		return GnuUtils.isGnuCompiler(program);
	}

	@Override
	public RttiScanner getScanner(Program program) {
		return new ItaniumAbiRttiScanner(program);
	}

}
