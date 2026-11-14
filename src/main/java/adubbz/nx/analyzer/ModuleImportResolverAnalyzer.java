package adubbz.nx.analyzer;

import adubbz.nx.loader.SwitchLoader;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Links a Switch module's imports to the sibling modules of the same process.
 *
 * <p>An ExeFS (rtld, main, subsdk0..subsdk9, sdk) is linked by rtld into one process, and every
 * undefined symbol is looked up globally across the modules in load order. The loader leaves
 * those imports under {@code <EXTERNAL>/UNKNOWN}: the {@code DT_NEEDED} names it records
 * (e.g. {@code nnSdk.nss}) don't match the module files, and Ghidra's own External Symbol
 * Resolver only runs on ELF/Mach-O programs.
 *
 * <p>This analyzer finds the sibling modules imported into the <em>same project folder</em>,
 * registers each as an external {@link Library} bound to that program, assigns library search
 * ordinals (Ghidra 12.2+) in rtld lookup order, and moves every {@code UNKNOWN} import to the
 * first sibling that exports it. The original import name is used, so imports the demangler has
 * already put in nested namespaces ({@code <EXTERNAL>::nn::fs::...}) are found too, and their
 * namespace path is recreated under the target library. Ghidra's ExternalSymbolResolver only
 * handles direct children of {@code UNKNOWN}, so it would miss those after analysis.
 *
 * <p>Exposed to scripts through {@link #resolve} (see
 * {@code ghidra_scripts/ResolveSwitchModuleImports.java}).
 */
public class ModuleImportResolverAnalyzer extends AbstractAnalyzer
{
    public static final String NAME = "(Switch) Module Import Resolver";
    private static final String DESCRIPTION =
        "Links imports in <EXTERNAL>/UNKNOWN to sibling ExeFS modules (main, subsdkN, sdk) " +
        "imported into the same project folder, searched in rtld load order.";

    public static final String OPTION_SEARCH_ORDER = "Module search order";
    private static final String OPTION_SEARCH_ORDER_DESC =
        "Comma-separated project file names of the sibling modules, in rtld symbol search " +
        "order. The program being analyzed is skipped. A name also matches the same name " +
        "with an .nso extension.";
    public static final String DEFAULT_SEARCH_ORDER =
        "main,subsdk0,subsdk1,subsdk2,subsdk3,subsdk4,subsdk5,subsdk6,subsdk7,subsdk8,subsdk9,sdk";

    private String searchOrder = DEFAULT_SEARCH_ORDER;

    public ModuleImportResolverAnalyzer()
    {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        // Same slot as Ghidra's External Symbol Resolver: after functions (and with them the
        // EXTERNAL-block thunks) exist, before demangling.
        this.setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before().before());
        this.setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program)
    {
        return true;
    }

    @Override
    public boolean canAnalyze(Program program)
    {
        return SwitchLoader.SWITCH_NAME.equals(program.getExecutableFormat()) &&
            program.getDomainFile().getParent() != null;
    }

    @Override
    public void registerOptions(Options options, Program program)
    {
        options.registerOption(OPTION_SEARCH_ORDER, DEFAULT_SEARCH_ORDER, null, OPTION_SEARCH_ORDER_DESC);
    }

    @Override
    public void optionsChanged(Options options, Program program)
    {
        this.searchOrder = options.getString(OPTION_SEARCH_ORDER, DEFAULT_SEARCH_ORDER);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        Result result = resolve(program, parseSearchOrder(this.searchOrder), monitor, s -> Msg.info(this, s));

        if (!result.problems().isEmpty())
            log.appendMsg(NAME + ": could not open " + String.join(", ", result.problems()) + ", see the log for details.");

        return true;
    }

    /**
     * Outcome of a {@link #resolve} run.
     *
     * @param resolvedPerModule imports moved by this run, per sibling module, in search order
     * @param unresolved imports still in {@code UNKNOWN} afterwards
     * @param problems sibling modules that were found but could not be opened
     */
    public record Result(Map<String, Integer> resolvedPerModule, int unresolved, List<String> problems)
    {
        public int resolved()
        {
            return resolvedPerModule.values().stream().mapToInt(Integer::intValue).sum();
        }
    }

    public static List<String> parseSearchOrder(String order)
    {
        List<String> names = new ArrayList<>();

        if (order == null)
            return names;

        for (String part : order.split(","))
        {
            String name = part.trim();
            if (!name.isEmpty() && !names.contains(name))
                names.add(name);
        }

        return names;
    }

    /**
     * Registers the sibling modules of {@code program} as ordered external libraries and moves
     * every {@code UNKNOWN} import to the first sibling (in {@code searchOrder}) that exports it.
     *
     * <p>Must be called inside a transaction on {@code program}. Sibling programs are opened
     * read-only and released before returning. Safe to run again: libraries already bound to a
     * path keep it, and imports that were already moved out of {@code UNKNOWN} are left alone.
     *
     * @param program the module to fix up; must be saved in a project folder
     * @param searchOrder sibling file names in rtld search order
     * @param monitor task monitor
     * @param logger receives a per-library summary
     */
    public static Result resolve(Program program, List<String> searchOrder, TaskMonitor monitor, Consumer<String> logger) throws CancelledException
    {
        DomainFile self = program.getDomainFile();
        DomainFolder folder = self.getParent();
        Result empty = new Result(Map.of(), 0, List.of());

        if (folder == null)
        {
            logger.accept(NAME + ": " + program.getName() + " is not saved in a project folder, skipping.");
            return empty;
        }

        List<Symbol> imports = getUnknownImports(program);

        if (imports.isEmpty())
        {
            logger.accept(NAME + ": " + self.getName() + " has no imports in " + Library.UNKNOWN +
                ", nothing to resolve. (Imports that are untyped in the module's symbol table only " +
                "appear there once auto-analysis has created functions for them.)");
            return empty;
        }

        Map<String, DomainFile> siblings = new LinkedHashMap<>();

        for (String name : searchOrder)
        {
            DomainFile sibling = findSibling(folder, name);

            if (sibling != null && !sibling.getPathname().equals(self.getPathname()))
                siblings.put(name, sibling);
        }

        if (siblings.isEmpty())
        {
            logger.accept(String.format("%s: no sibling modules of %s found in %s (searched: %s), %d imports left in %s.",
                NAME, self.getName(), folder.getPathname(), String.join(",", searchOrder), imports.size(), Library.UNKNOWN));
            return new Result(Map.of(), imports.size(), List.of());
        }

        // Load each sibling's export names once (opened read-only, released straight away).
        Map<String, Set<String>> exports = new LinkedHashMap<>();
        List<String> problems = new ArrayList<>();
        Object consumer = new Object();

        for (Map.Entry<String, DomainFile> e : siblings.entrySet())
        {
            monitor.checkCancelled();
            monitor.setMessage("Reading exports of " + e.getKey() + "...");

            try
            {
                Program sibling = (Program) e.getValue().getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);

                try
                {
                    exports.put(e.getKey(), getExportNames(sibling));
                }
                finally
                {
                    sibling.release(consumer);
                }
            }
            catch (CancelledException ce)
            {
                throw ce;
            }
            catch (Exception ex)
            {
                Msg.error(ModuleImportResolverAnalyzer.class, "Could not open " + e.getValue().getPathname() + ": " + ex.getMessage(), ex);
                problems.add(e.getValue().getPathname());
            }
        }

        ExternalManager extManager = program.getExternalManager();
        SymbolTable symbolTable = program.getSymbolTable();
        Map<String, Integer> resolved = new LinkedHashMap<>();
        Set<String> created = new HashSet<>();
        int ordinal = 1;

        for (String name : exports.keySet())
        {
            try
            {
                if (extManager.getExternalLibrary(name) == null)
                    created.add(name);

                // Keep a path the user already bound by hand (Window > External Programs).
                if (extManager.getExternalLibraryPath(name) == null)
                    extManager.setExternalPath(name, siblings.get(name).getPathname(), false);

                extManager.setLibraryOrdinal(name, ordinal++);
                resolved.put(name, 0);
            }
            catch (Exception ex)
            {
                Msg.error(ModuleImportResolverAnalyzer.class, "Could not register library " + name, ex);
            }
        }

        monitor.setMessage("Linking imports to sibling modules...");
        monitor.initialize(imports.size());
        List<Namespace> touched = new ArrayList<>();
        int unresolved = 0;

        for (Symbol s : imports)
        {
            monitor.increment();
            ExternalLocation extLoc = extManager.getExternalLocation(s);
            String importName = extLoc == null ? s.getName()
                : Objects.requireNonNullElse(extLoc.getOriginalImportedName(), extLoc.getLabel());
            String target = null;

            for (String name : resolved.keySet())
            {
                if (exports.get(name).contains(importName))
                {
                    target = name;
                    break;
                }
            }

            if (target == null)
            {
                unresolved++;
                continue;
            }

            try
            {
                Namespace oldParent = s.getParentNamespace();
                s.setNamespace(mirrorNamespace(symbolTable, oldParent, extManager.getExternalLibrary(target)));
                resolved.merge(target, 1, Integer::sum);

                if (!(oldParent instanceof Library))
                    touched.add(oldParent);
            }
            catch (Exception ex)
            {
                Msg.error(ModuleImportResolverAnalyzer.class, "Could not move import " + s.getName(true) + " to " + target, ex);
                unresolved++;
            }
        }

        // Remove namespaces under UNKNOWN that the move emptied (e.g. <EXTERNAL>::nn::fs).
        for (Namespace ns : touched)
            removeIfEmpty(symbolTable, ns);

        // Drop libraries this run created but which ended up with no imports; a later run
        // (after more siblings are imported) re-creates them.
        for (String name : created)
        {
            if (resolved.getOrDefault(name, 0) == 0)
            {
                extManager.removeExternalLibrary(name);
                resolved.remove(name);
            }
        }

        logger.accept("Resolving External Symbols of [" + self.getPathname() + "] - Summary");
        logger.accept(String.format("\t%d external symbols resolved, %d remain unresolved", imports.size() - unresolved, unresolved));

        for (Map.Entry<String, Integer> e : resolved.entrySet())
            logger.accept(String.format("\t[%s] -> %s, %d new symbols resolved", e.getKey(), siblings.get(e.getKey()).getPathname(), e.getValue()));

        for (String p : problems)
            logger.accept("\t" + p + ": could not be opened");

        return new Result(resolved, unresolved, problems);
    }

    /**
     * External functions (non-default source) whose library is {@code UNKNOWN}, including ones
     * the demangler moved into nested namespaces.
     */
    private static List<Symbol> getUnknownImports(Program program)
    {
        List<Symbol> result = new ArrayList<>();

        for (Symbol s : program.getSymbolTable().getExternalSymbols())
        {
            if (s.getSymbolType() != SymbolType.FUNCTION || s.getSource() == SourceType.DEFAULT)
                continue;

            Library lib = getLibrary(s.getParentNamespace());

            if (lib != null && Library.UNKNOWN.equals(lib.getName()))
                result.add(s);
        }

        return result;
    }

    private static Library getLibrary(Namespace ns)
    {
        while (ns != null && !ns.isGlobal())
        {
            if (ns instanceof Library lib)
                return lib;

            ns = ns.getParentNamespace();
        }

        return null;
    }

    /**
     * The program's dynamic export names: loader-created ({@link SourceType#IMPORTED}) symbols at
     * its external entry points. Symbols added later by analysis are ignored; in an analyzed
     * sibling the demangler puts e.g. {@code Foo::remove} at an export address, and its bare
     * name would otherwise match an unrelated C import {@code remove}.
     */
    private static Set<String> getExportNames(Program program)
    {
        Set<String> names = new HashSet<>();
        SymbolTable symbolTable = program.getSymbolTable();
        AddressIterator it = symbolTable.getExternalEntryPointIterator();

        while (it.hasNext())
        {
            Address addr = it.next();

            for (Symbol s : symbolTable.getSymbols(addr))
            {
                if (s.getSource() == SourceType.IMPORTED)
                    names.add(s.getName());
            }
        }

        return names;
    }

    /**
     * Returns the namespace under {@code library} with the same path that {@code ns} has under
     * its own library, creating missing parts (classes stay classes).
     */
    private static Namespace mirrorNamespace(SymbolTable symbolTable, Namespace ns, Library library) throws Exception
    {
        Deque<Namespace> path = new ArrayDeque<>();

        while (ns != null && !(ns instanceof Library) && !ns.isGlobal())
        {
            path.push(ns);
            ns = ns.getParentNamespace();
        }

        Namespace parent = library;

        for (Namespace part : path)
        {
            Namespace existing = symbolTable.getNamespace(part.getName(), parent);

            if (existing == null)
            {
                existing = part instanceof GhidraClass
                    ? symbolTable.createClass(parent, part.getName(), SourceType.IMPORTED)
                    : symbolTable.createNameSpace(parent, part.getName(), SourceType.IMPORTED);
            }

            parent = existing;
        }

        return parent;
    }

    private static void removeIfEmpty(SymbolTable symbolTable, Namespace ns)
    {
        while (ns != null && !(ns instanceof Library) && !ns.isGlobal())
        {
            Symbol sym = ns.getSymbol();

            if (sym == null || sym.isDeleted() || symbolTable.getChildren(sym).hasNext())
                return;

            Namespace parent = ns.getParentNamespace();
            sym.delete();
            ns = parent;
        }
    }

    private static DomainFile findSibling(DomainFolder folder, String name)
    {
        for (String candidate : new String[] { name, name + ".nso" })
        {
            DomainFile file = folder.getFile(candidate);

            if (file != null && ProgramDB.CONTENT_TYPE.equals(file.getContentType()))
                return file;
        }

        return null;
    }
}
