package cppclassanalyzer.plugin.typemgr.filter;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFileFilter;
import ghidra.program.model.listing.DataTypeArchive;

public class ProjectArchiveFilter implements DomainFileFilter {

	public static final ProjectArchiveFilter FILTER = new ProjectArchiveFilter();

	private ProjectArchiveFilter() {
	}

	@Override
	public boolean accept(DomainFile df) {
		Class<?> c = df.getDomainObjectClass();
		return DataTypeArchive.class.isAssignableFrom(c);
	}
}
