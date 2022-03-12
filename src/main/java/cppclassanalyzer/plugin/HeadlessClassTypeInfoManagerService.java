package cppclassanalyzer.plugin;

import java.awt.HeadlessException;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.data.rtti.gcc.UnresolvedClassTypeInfoException;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import cppclassanalyzer.data.ArchivedRttiData;
import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.*;
import cppclassanalyzer.data.typeinfo.ArchivedClassTypeInfo;
import cppclassanalyzer.data.vtable.ArchivedVtable;
import cppclassanalyzer.database.SchemaMismatchException;
import cppclassanalyzer.decompiler.DecompilerAPI;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.service.RttiManagerProvider;
import docking.widgets.tree.GTree;

public final class HeadlessClassTypeInfoManagerService implements ClassTypeInfoManagerService {

	protected final DecompilerAPI api;
	protected final List<ClassTypeInfoManager> managers;
	protected ProgramClassTypeInfoManager currentManager;

	private static HeadlessClassTypeInfoManagerService instance;

	public static HeadlessClassTypeInfoManagerService getInstance() {
		if (instance == null) {
			instance = new HeadlessClassTypeInfoManagerService();
		}
		return instance;
	}

	private HeadlessClassTypeInfoManagerService() {
		this.api = new DecompilerAPI((PluginTool) null);
		this.managers = Collections.synchronizedList(new ArrayList<>());
	}

	protected ProgramClassTypeInfoManager programOpened(Program program) {
		try {
			RttiManagerProvider provider =
				ClassTypeInfoManagerService.getManagerProvider(program);
			if (provider != null) {
				ProgramClassTypeInfoManager manager = provider.getManager(program);
				managers.add(manager);
				program.addCloseListener(new ManagerRemover(program));
				return manager;
			}
		} catch (SchemaMismatchException e) {
			Msg.showError(this, null, "Ghidra C++ Class Analyzer", e.getMessage());
		} catch (UnsupportedOperationException e) {
			// do nothing
		}
		return null;
	}

	protected void programClosed(Program program) {
		ClassTypeInfoManager man = getManager(program);
		if (man != null) {
			managers.remove(getManager(program));
		}
	}

	protected void programActivated(Program program) {
		currentManager = getManager(program);
	}

	protected void programDeactivated(Program program) {
		ClassTypeInfoManager manager = getManager(program);
		if (currentManager != null && currentManager.equals(manager)) {
			currentManager = null;
		}
	}

	@Override
	public List<ClassTypeInfoManager> getManagers() {
		return Collections.unmodifiableList(managers);
	}

	@Override
	public void closeManager(ClassTypeInfoManager manager) {
		if (manager instanceof FileArchiveClassTypeInfoManager) {
			((FileArchiveClassTypeInfoManager) manager).close();
		}
	}

	@Override
	public void openArchive(File file, boolean updateable) throws IOException {
		ClassTypeInfoManager manager =
			ArchiveClassTypeInfoManager.open(this, file, updateable);
		managers.add(manager);
	}

	@Override
	public void createArchive(File file) throws IOException {
		ClassTypeInfoManager manager = ArchiveClassTypeInfoManager.createManager(this, file);
		managers.add(manager);
	}

	@Override
	public DecompilerAPI getDecompilerAPI(Program program) {
		api.setProgram(program);
		return api;
	}

	public List<ClassTypeInfoManager> getManagersByName(List<String> names) {
		return managers.stream()
			.filter(m -> names.contains(m.getName()))
			.collect(Collectors.toList());
	}

	public boolean hasManager(ProjectArchive archive) {
		String name = archive.getName();
		return managers.stream()
			.filter(ProjectClassTypeInfoManager.class::isInstance)
			.map(ClassTypeInfoManager::getName)
			.anyMatch(name::equals);
	}

	public void openProjectArchive(ProjectArchive archive) throws IOException {
		ClassTypeInfoManager manager = ProjectClassTypeInfoManager.open(this, archive);
		projectManagerOpened(manager);
	}

	private void projectManagerOpened(ClassTypeInfoManager manager) {
		managers.add(manager);
	}

	@Override
	public ProgramClassTypeInfoManager getManager(Program program) {
		ProgramClassTypeInfoManager manager = managers.stream()
			.filter(ProgramClassTypeInfoManager.class::isInstance)
			.map(ProgramClassTypeInfoManager.class::cast)
			.filter(m -> m.getProgram().equals(program))
			.findAny()
			.orElse(null);
		if (manager == null) {
			manager = programOpened(program);
		}
		return manager;
	}

	@Override
	public ProgramClassTypeInfoManager getCurrentManager() {
		return currentManager;
	}

	@Override
	public ArchivedClassTypeInfo getExternalClassTypeInfo(Program program, String mangled) {
		String[] libs = program.getExternalManager().getExternalLibraryNames();
		List<LibraryClassTypeInfoManager> libManagers = managers.stream()
			.filter(ProjectClassTypeInfoManager.class::isInstance)
			.map(ProjectClassTypeInfoManager.class::cast)
			.flatMap(m -> m.getAvailableManagers(libs))
			.collect(Collectors.toList());
		for (LibraryClassTypeInfoManager manager : libManagers) {
			ArchivedClassTypeInfo type = manager.getType(mangled);
			if (type != null) {
				return type;
			}
		}
		throw new UnresolvedClassTypeInfoException(program, mangled);
	}

	@Override
	public ArchivedClassTypeInfo getArchivedClassTypeInfo(String symbolName) {
		return getArchivedRttiData(ArchivedClassTypeInfo.class, symbolName);
	}

	@Override
	public ArchivedVtable getArchivedVtable(String symbolName) {
		return getArchivedRttiData(ArchivedVtable.class, symbolName);
	}

	private <T extends ArchivedRttiData> T getArchivedRttiData(Class<T> clazz, String symbolName) {
		return managers.stream()
			.filter(ProjectClassTypeInfoManager.class::isInstance)
			.map(ProjectClassTypeInfoManager.class::cast)
			.map(m -> m.getRttiData(clazz, symbolName))
			.filter(Objects::nonNull)
			.findFirst()
			.orElse(null);
	}

	@Override
	public GTree getTree() {
		throw new HeadlessException();
	}

	private class ManagerRemover implements DomainObjectClosedListener {

		private final Program program;

		ManagerRemover(Program program) {
			this.program = program;
		}

		@Override
		public void domainObjectClosed() {
			programClosed(program);
		}
	}

}
