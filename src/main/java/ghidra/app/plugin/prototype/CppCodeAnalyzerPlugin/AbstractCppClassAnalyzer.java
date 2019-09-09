package ghidra.app.plugin.prototype.CppCodeAnalyzerPlugin;

import java.util.*;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.FunctionParameterFieldLocation;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.util.ConsoleErrorDisplay;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;

public abstract class AbstractCppClassAnalyzer extends AbstractAnalyzer {

    private static final String DESCRIPTION = "This analyzer analyzes RTTI metadata to recreate classes and their functions";

    private static final String OPTION_VTABLE_ANALYSIS_NAME = "Locate Constructors";
    private static final boolean OPTION_DEFAULT_VTABLE_ANALYSIS = true;
    private static final String OPTION_VTABLE_ANALYSIS_DESCRIPTION = "Turn on to search for Constructors/Destructors.";

    private static final String OPTION_FILLER_ANALYSIS_NAME = "Fill Class Fields";
    private static final boolean OPTION_DEFAULT_FILLER_ANALYSIS = true;
    private static final String OPTION_FILLER_ANALYSIS_DESCRIPTION = "Turn on to fill out the found class structures.";

    private boolean constructorAnalysisOption;
    private boolean fillClassFieldsOption;

    protected Program program;
    private TaskMonitor monitor;
    private CancelOnlyWrappingTaskMonitor dummy;
    private AutoAnalysisManager analysisManager;

    private List<ClassTypeInfo> classes;
    private ArrayList<Vtable> vftables;

    protected AbstractConstructorAnalysisCmd constructorAnalyzer;

    protected MessageLog log;

    /**
     * Constructs an AbstractCppClassAnalyzer.
     */
    public AbstractCppClassAnalyzer(String name) {
        super(name, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setSupportsOneTimeAnalysis();
        setDefaultEnablement(true);
        setPrototype();
    }

    protected abstract boolean hasVtt();

    protected abstract List<ClassTypeInfo> getClassTypeInfoList();

    protected abstract AbstractConstructorAnalysisCmd getConstructorAnalyzer();

    @Override
    @SuppressWarnings("hiding")
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        this.program = program;
        this.monitor = monitor;
        this.log = log;
        this.analysisManager = AutoAnalysisManager.getAnalysisManager(program);
        this.constructorAnalyzer = getConstructorAnalyzer();

        dummy = new CancelOnlyWrappingTaskMonitor(monitor);
        classes = getClassTypeInfoList();

        try {
            setupVftables();
            analyzeVftables();
            if (fillClassFieldsOption) {
                fillStructures();
            }
            return true;
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            log.appendException(e);
            return false;
        }
    }

    @Override
    @SuppressWarnings("hiding")
    public void analysisEnded(Program program) {
        classes = null;
        vftables = null;
        super.analysisEnded(program);
    }

    private void setupVftables() throws CancelledException, InvalidDataTypeException {
        vftables = new ArrayList<>(classes.size());
        monitor.initialize(classes.size());
        monitor.setMessage("Locating vftables...");
        for (ClassTypeInfo type : classes) {
            monitor.checkCanceled();
            Vtable vftable = type.getVtable();
            try {
                vftable.validate();
                vftables.add(vftable);
            } catch (InvalidDataTypeException e) {}
            monitor.incrementProgress(1);
        }
    }

    private void repairInheritance() throws CancelledException, InvalidDataTypeException {
        monitor.initialize(classes.size());
        monitor.setMessage("Fixing Class Inheritance...");
        for (ClassTypeInfo type : classes) {
            monitor.checkCanceled();
            if (type.getName().contains(TypeInfoModel.STRUCTURE_NAME)) {
                // this works for both vs and gcc
                continue;
            }
            type.getClassDataType(true);
            monitor.incrementProgress(1);
        }
    }

    private void fillStructures() throws CancelledException, InvalidDataTypeException {
        SymbolTable table = program.getSymbolTable();
        PluginTool tool = analysisManager.getAnalysisTool();
        repairInheritance();
        if (constructorAnalysisOption) {
            monitor.initialize(vftables.size());
            monitor.setMessage("Filling Class Structures...");
            Msg.setErrorDisplay(new ConsoleErrorDisplay());
            for (Vtable vtable : vftables) {
                ClassTypeInfo type = vtable.getTypeInfo();
                if (type.getName().contains(TypeInfoModel.STRUCTURE_NAME)) {
                    continue;
                }
                GhidraClass gc = type.getGhidraClass();
                for (Symbol symbol : table.getChildren(gc.getSymbol())) {
                    monitor.checkCanceled();
                    if(!symbol.getSymbolType().equals(SymbolType.FUNCTION)) {
                        continue;
                    }
                    Function function = getFunction(symbol.getAddress());
                    if (function == null) {
                        Msg.error(this, "Null function at: "+symbol.getAddress());
                    }
                    Parameter thisParam = function.getParameter(0);
                    FunctionParameterFieldLocation location = new FunctionParameterFieldLocation(
                        program, symbol.getAddress(), symbol.getAddress(),
                        0, function.getSignature().toString(), thisParam);
                    FillOutStructureCmd cmd = new FillOutStructureCmd(program, location, tool);
                    try {
                        cmd.applyTo(program, dummy);
                    } catch (Exception e) {
                        Msg.error(this, "Failed to populate class structure.", e);
                    }
                }
                monitor.incrementProgress(1);
            }
            repairInheritance();
        }
    }

    private Function getFunction(Address address) {
        Listing listing = program.getListing();
        if (listing.getInstructionAt(address) == null) {
            DisassembleCommand cmd = new DisassembleCommand(address, null, true);
            if (!cmd.applyTo(program)) {
                return null;
            }
        }
        FunctionManager manager = program.getFunctionManager();
        Function function = manager.getFunctionContaining(address);
        if (function == null) {
            CreateFunctionCmd cmd = new CreateFunctionCmd(address, true);
            if (cmd.applyTo(program)) {
                return cmd.getFunction();
            }
        }
        return function;
    }

    

    protected void analyzeVftables() throws Exception {
        List<ClassTypeInfo> namespaces = new ArrayList<>(vftables.size());
        monitor.initialize(vftables.size());
        monitor.setMessage("Setting up namespaces");
        for (Vtable vtable : vftables) {
            monitor.checkCanceled();
            ClassTypeInfo type = vtable.getTypeInfo();
            try {
                type.validate();
            } catch (InvalidDataTypeException e) {
                continue;
            }
            namespaces.add(type);
            monitor.incrementProgress(1);
        }
        ClassTypeInfoUtils.sortByMostDerived(program, namespaces);
        monitor.initialize(vftables.size());
        monitor.setMessage("Analyzing Vftables");
        for (ClassTypeInfo type : namespaces) {
            monitor.checkCanceled();
            analyzeVftable(type);
            monitor.incrementProgress(1);
        }
        Collections.reverse(namespaces);
        if (constructorAnalysisOption) {
            analyzeConstructors(namespaces);
        }
    }

    protected abstract boolean analyzeVftable(ClassTypeInfo type);
    protected abstract boolean analyzeConstructor(ClassTypeInfo type);

    protected boolean shouldAnalyzeConstructors() {
        return constructorAnalysisOption;
    }

    protected void analyzeConstructors(List<ClassTypeInfo> namespaces) throws Exception {
        monitor.initialize(namespaces.size());
        monitor.setMessage("Creating Constructors");
        for (ClassTypeInfo type : namespaces) {
            monitor.checkCanceled();
            analyzeConstructor(type);
            monitor.incrementProgress(1);
        }
    }
    
    @SuppressWarnings("hiding")
    @Override
	public void optionsChanged(Options options, Program program) {
        super.optionsChanged(options, program);
        options.registerOption(OPTION_VTABLE_ANALYSIS_NAME, OPTION_DEFAULT_VTABLE_ANALYSIS, null,
            OPTION_VTABLE_ANALYSIS_DESCRIPTION);
        options.registerOption(OPTION_FILLER_ANALYSIS_NAME, OPTION_DEFAULT_FILLER_ANALYSIS, null,
            OPTION_FILLER_ANALYSIS_DESCRIPTION);

        constructorAnalysisOption =
            options.getBoolean(OPTION_VTABLE_ANALYSIS_NAME, OPTION_DEFAULT_VTABLE_ANALYSIS);
        fillClassFieldsOption =
            options.getBoolean(OPTION_FILLER_ANALYSIS_NAME, OPTION_DEFAULT_FILLER_ANALYSIS);
    }
}
