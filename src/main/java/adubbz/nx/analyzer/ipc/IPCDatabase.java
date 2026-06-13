package adubbz.nx.analyzer.ipc;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.util.Msg;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * IPC interface/command reference data, loaded from {@code /ipc_database.json}.
 *
 * <p>Schema (Switchbrew-derived, grouped by wiki page):
 * <pre>
 * {
 *   "Services:": {
 *     "Filesystem_services": {                                   // wiki page (grouping only)
 *       "fsp-srv": {                                             // sm service / interface heading
 *         "nn::fssrv::sf::IFileSystemProxy": {                   // the interface it exposes
 *           "1": "SetCurrentProcess",                            // plain name
 *           "400": { "name": "OpenDeviceOperator",               // name + out-interface
 *                    "out": "nn::fssrv::sf::IDeviceOperator" }
 *         }
 *       },
 *       "IFileSystem": { "nn::fssrv::sf::IFileSystem": { ... } }
 *     }
 *   }
 * }
 * </pre>
 * A command value is either a string (just the name) or an object with {@code name} and optional
 * {@code out} (the interface it returns). The old top-level {@code _services} map is gone: the
 * service-&gt;interface mapping is derived from the heading key (which may list several comma-joined
 * sm names) and the interface name nested under it. Keys beginning with {@code _} ({@code _NOTE},
 * {@code _disabled_*}) are reserved and skipped. The heading key may carry a trailing
 * {@code (annotation)} which is stripped when reading service names.
 */
public class IPCDatabase
{
    private final Map<String, Map<String, String>> db;             // interface -> cmd -> name
    private final Map<String, Map<String, String>> outInterfaces;  // interface -> cmd -> out-interface
    private final Map<String, List<String>> serviceInterfaces;     // sm service -> candidate root interface(s)
    private final Map<String, Set<String>> interfacePrograms;      // interface -> program (wiki-page) key(s)
    private final Map<String, List<String>> programInterfaces;     // program (wiki-page) key -> interfaces

    private static IPCDatabase instance;

    private IPCDatabase(Map<String, Map<String, String>> db,
                        Map<String, Map<String, String>> outInterfaces,
                        Map<String, List<String>> serviceInterfaces,
                        Map<String, Set<String>> interfacePrograms,
                        Map<String, List<String>> programInterfaces)
    {
        this.db = db;
        this.outInterfaces = outInterfaces;
        this.serviceInterfaces = serviceInterfaces;
        this.interfacePrograms = interfacePrograms;
        this.programInterfaces = programInterfaces;
    }

    public static IPCDatabase getInstance()
    {
        if (instance == null)
        {
            Map<String, Map<String, String>> db = new HashMap<>();
            Map<String, Map<String, String>> outs = new HashMap<>();
            Map<String, List<String>> services = new HashMap<>();
            Map<String, Set<String>> interfacePrograms = new HashMap<>();
            Map<String, List<String>> programInterfaces = new HashMap<>();
            int malformed = 0;

            try (InputStream is = IPCDatabase.class.getResourceAsStream("/ipc_database.json");
                 InputStreamReader reader = new InputStreamReader(is))
            {
                JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();
                JsonElement servicesEl = root.get("Services:");

                if (servicesEl == null || !servicesEl.isJsonObject())
                    throw new IllegalStateException("missing top-level \"Services:\" object");

                // Top-level reference sections (every root key other than "Services:", e.g. "Framework:")
                // hold shared interface definitions that a Services: entry points at via {"_ref": "<name>"}.
                // Keyed by the bare name (trailing ':' stripped) -> interface fullname -> command object.
                Map<String, Map<String, JsonObject>> refSections = new HashMap<>();
                for (Map.Entry<String, JsonElement> top : root.entrySet())
                {
                    if (top.getKey().equals("Services:") || top.getValue() == null || !top.getValue().isJsonObject())
                        continue;
                    String sectionName = top.getKey().endsWith(":")
                        ? top.getKey().substring(0, top.getKey().length() - 1) : top.getKey();
                    Map<String, JsonObject> defs = new HashMap<>();
                    for (Map.Entry<String, JsonElement> e : top.getValue().getAsJsonObject().entrySet())
                        if (e.getValue() != null && e.getValue().isJsonObject())
                            defs.put(e.getKey(), e.getValue().getAsJsonObject());
                    refSections.put(sectionName, defs);
                }

                // Services: -> <wiki page> -> <heading> -> <interface fullname> -> commands
                for (Map.Entry<String, JsonElement> page : servicesEl.getAsJsonObject().entrySet())
                {
                    if (page.getValue() == null || !page.getValue().isJsonObject())
                        continue;

                    String program = page.getKey();   // the wiki-page key == the "program" grouping

                    for (Map.Entry<String, JsonElement> entry : page.getValue().getAsJsonObject().entrySet())
                    {
                        if (entry.getValue() == null || !entry.getValue().isJsonObject())
                            continue;

                        // The heading key may bundle several comma-joined sm service names and a
                        // trailing "(annotation)"; the interface itself is the nested "nn::..." key.
                        List<String> serviceNames = parseServiceNames(entry.getKey());
                        boolean foundInterface = false;

                        for (Map.Entry<String, JsonElement> iface : entry.getValue().getAsJsonObject().entrySet())
                        {
                            String ifaceName = iface.getKey();

                            if (ifaceName.startsWith("_"))           // _NOTE, _disabled_*
                                continue;
                            if (!ifaceName.contains("::") || !iface.getValue().isJsonObject())
                                continue;                            // not an interface fullname

                            foundInterface = true;
                            JsonObject ifaceBody = iface.getValue().getAsJsonObject();
                            mergeCommands(db, outs, ifaceName, ifaceBody);

                            // Framework interfaces (IHipcManager, IHOSBinderDriver, ...) are listed per
                            // program as {"_ref": "Framework"} stubs; pull their command names from the
                            // referenced section so they don't fall to NOT_IN_DATABASE.
                            if (ifaceBody.has("_ref") && ifaceBody.get("_ref").isJsonPrimitive())
                            {
                                Map<String, JsonObject> section = refSections.get(ifaceBody.get("_ref").getAsString());
                                JsonObject def = section != null ? section.get(ifaceName) : null;
                                if (def != null)
                                    mergeCommands(db, outs, ifaceName, def);
                            }

                            interfacePrograms.computeIfAbsent(ifaceName, k -> new HashSet<>()).add(program);
                            // Keep DUPLICATES in order: the same interface fullname may be listed under
                            // several headings on purpose (e.g. IAsyncValue1/IAsyncValue2) to represent
                            // an interface that recurs at multiple positions, which positional inference
                            // needs in order to fill repeated SRV_ slots.
                            programInterfaces.computeIfAbsent(program, k -> new ArrayList<>()).add(ifaceName);

                            for (String svc : serviceNames)
                            {
                                List<String> candidates = services.computeIfAbsent(svc, k -> new ArrayList<>());
                                if (!candidates.contains(ifaceName))
                                    candidates.add(ifaceName);
                            }
                        }

                        if (!foundInterface)
                            malformed++;   // note-only / placeholder / missing-interface-wrapper entry
                    }
                }

                Msg.info(IPCDatabase.class, String.format(
                    "Loaded IPC database with %d interfaces, %d with out-interfaces, %d service mappings, %d programs (%d entries without an interface)",
                    db.size(), outs.size(), services.size(), programInterfaces.size(), malformed));
            }
            catch (Exception e)
            {
                Msg.warn(IPCDatabase.class, "Failed to load IPC database, command names will not be resolved: " + e.getMessage());
            }

            instance = new IPCDatabase(db, outs, services, interfacePrograms, programInterfaces);
        }
        return instance;
    }

    /** Parse a command map ({@code "<cmd>": "Name"} or {@code {"name":..,"out":..}}) into the
     *  name and out-interface tables, merging into any commands already recorded for this interface
     *  (the same interface fullname appears under several wiki pages). */
    private static void mergeCommands(Map<String, Map<String, String>> db,
                                      Map<String, Map<String, String>> outs,
                                      String ifaceName, JsonObject commands)
    {
        Map<String, String> names = db.computeIfAbsent(ifaceName, k -> new HashMap<>());

        for (Map.Entry<String, JsonElement> cmd : commands.entrySet())
        {
            if (cmd.getKey().startsWith("_"))   // _NOTE inside an otherwise-empty interface
                continue;

            JsonElement v = cmd.getValue();
            if (v != null && v.isJsonPrimitive())
            {
                names.put(cmd.getKey(), v.getAsString());
            }
            else if (v != null && v.isJsonObject())
            {
                JsonObject o = v.getAsJsonObject();
                if (o.has("name") && o.get("name").isJsonPrimitive())
                    names.put(cmd.getKey(), o.get("name").getAsString());
                if (o.has("out") && o.get("out").isJsonPrimitive())
                    outs.computeIfAbsent(ifaceName, k -> new HashMap<>()).put(cmd.getKey(), o.get("out").getAsString());
            }
        }
    }

    /** Extract the sm service names from a heading key, e.g.
     *  {@code "nifm:a, nifm:s, nifm:u"} or {@code "lbl (MOVED TO PTM 10.0.0+)"}. */
    private static List<String> parseServiceNames(String headingKey)
    {
        List<String> out = new ArrayList<>();
        String stripped = headingKey.replaceAll("\\(.*?\\)", " ");   // drop trailing annotations
        for (String token : stripped.split(","))
        {
            String svc = token.trim();
            if (!svc.isEmpty())
                out.add(svc);
        }
        return out;
    }

    /**
     * Looks up a command name for a given interface and command ID. The interface name is matched
     * exactly, then by suffix, to handle full demangled names and shortened ones.
     *
     * @return the command name, or null if not found
     */
    public String getCommandName(String interfaceName, long cmdId)
    {
        return lookup(this.db, interfaceName, cmdId);
    }

    /**
     * The interface returned by a given command of a given interface (its out-interface), e.g.
     * {@code IFileSystemProxy} cmd 400 -&gt; {@code nn::fssrv::sf::IDeviceOperator}. Null if unknown.
     */
    public String getOutInterface(String interfaceName, long cmdId)
    {
        return lookup(this.outInterfaces, interfaceName, cmdId);
    }

    /**
     * The root interface a sm service connects to, e.g. {@code "fsp-srv"} -&gt; IFileSystemProxy.
     * When a service maps to several candidate interfaces (the same port name backed by different
     * interfaces across firmware versions), the candidate whose database command set best covers the
     * commands actually recovered from this module ({@code observedCommandIds}) is chosen, so naming
     * matches the firmware actually being analysed. Returns null if the service has no mapping.
     */
    public String getServiceInterface(String serviceName, Set<Long> observedCommandIds)
    {
        List<String> candidates = this.serviceInterfaces.get(serviceName);
        if (candidates == null || candidates.isEmpty())
            return null;
        if (candidates.size() == 1)
            return candidates.get(0);

        String best = candidates.get(0);
        int bestScore = -1;
        for (String candidate : candidates)
        {
            Map<String, String> cmds = this.db.get(candidate.replace("::vtable", "").trim());
            if (cmds == null)
                continue;

            int score = 0;
            if (observedCommandIds != null)
                for (Long id : observedCommandIds)
                    if (cmds.containsKey(String.valueOf(id))) score++;

            if (score > bestScore)
            {
                bestScore = score;
                best = candidate;
            }
        }
        return best;
    }

    private String lookup(Map<String, Map<String, String>> map, String interfaceName, long cmdId)
    {
        String iface = interfaceName.replace("::vtable", "").trim();
        String cmdKey = String.valueOf(cmdId);

        Map<String, String> exact = map.get(iface);
        if (exact != null)
            return exact.get(cmdKey);

        for (Map.Entry<String, Map<String, String>> entry : map.entrySet())
            if (entry.getKey().endsWith("::" + iface) || entry.getKey().equals(iface))
                return entry.getValue().get(cmdKey);

        return null;
    }

    public Map<String, Map<String, String>> getAllInterfaces()
    {
        return Collections.unmodifiableMap(db);
    }

    /** The program (wiki-page) key(s) this interface is listed under. An interface in exactly one
     *  program can identify that program; one in several (cross-program) cannot. Empty if unknown. */
    public Set<String> getProgramsForInterface(String interfaceName)
    {
        Set<String> programs = this.interfacePrograms.get(interfaceName);
        return programs != null ? Collections.unmodifiableSet(programs) : Collections.emptySet();
    }

    /** The interface returned by {@link #getProgramsForInterface} when, and only when, this interface
     *  belongs to exactly one program; otherwise null (cross-program, can't prove a program). */
    public String getSingleProgramForInterface(String interfaceName)
    {
        Set<String> programs = this.interfacePrograms.get(interfaceName);
        return programs != null && programs.size() == 1 ? programs.iterator().next() : null;
    }

    /** All interface fullnames listed under a program (wiki-page) key, in database order. */
    public List<String> getInterfacesForProgram(String program)
    {
        List<String> ifaces = this.programInterfaces.get(program);
        return ifaces != null ? Collections.unmodifiableList(ifaces) : Collections.emptyList();
    }
}
