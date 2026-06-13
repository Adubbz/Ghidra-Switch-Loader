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

public class IPCHashDatabase
{
    // Single flat map: structural hash -> interface name(s). Replaces the old current/legacy300 tiers.
    private final Map<String, List<String>> hashes;
    // Interfaces that share a hash with at least one other interface (the hash cannot uniquely name
    // them). Such interfaces must not be trusted to prove a program (see IPCAnalyzer layout inference).
    private final Set<String> collisionInterfaces;

    private static IPCHashDatabase instance;

    private IPCHashDatabase(Map<String, List<String>> hashes)
    {
        this.hashes = hashes;
        this.collisionInterfaces = new HashSet<>();
        for (List<String> ifaces : hashes.values())
            if (ifaces != null && ifaces.size() > 1)
                this.collisionInterfaces.addAll(ifaces);
    }

    public static IPCHashDatabase getInstance()
    {
        if (instance == null)
        {
            // Structured source, same schema as ipc_database.json:
            //   Services: -> <program> -> <heading> -> <interface fullname> -> { "_hash", "_hash_alt"? }
            // Flattened here into hash -> interface name(s) so matching is unchanged. Both _hash and
            // _hash_alt resolve to the interface; an interface listed under several programs/headings is
            // recorded once (de-duplicated) so it is not mistaken for a hash collision with itself.
            Map<String, List<String>> data = new HashMap<>();

            try (InputStream is = IPCHashDatabase.class.getResourceAsStream("/ipc_hashes.json");
                 InputStreamReader reader = new InputStreamReader(is))
            {
                JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();
                JsonElement servicesEl = root.get("Services:");

                if (servicesEl == null || !servicesEl.isJsonObject())
                    throw new IllegalStateException("missing top-level \"Services:\" object");

                for (Map.Entry<String, JsonElement> page : servicesEl.getAsJsonObject().entrySet())
                {
                    if (page.getValue() == null || !page.getValue().isJsonObject())
                        continue;

                    for (Map.Entry<String, JsonElement> heading : page.getValue().getAsJsonObject().entrySet())
                    {
                        if (heading.getValue() == null || !heading.getValue().isJsonObject())
                            continue;

                        for (Map.Entry<String, JsonElement> iface : heading.getValue().getAsJsonObject().entrySet())
                        {
                            String ifaceName = iface.getKey();

                            if (ifaceName.startsWith("_") || !ifaceName.contains("::")
                                || !iface.getValue().isJsonObject())
                                continue;

                            // Read EVERY "_hash*"-prefixed key (e.g. _hash, _hash_alt, _hash_21,
                            // _hash_22_1_0) and map each value to this interface. This lets the DB
                            // ACCUMULATE the structural hashes an interface has across firmware versions
                            // (each version's command layout is a different hash for the same interface),
                            // so every version still hash-PROVES rather than falling back to inference.
                            JsonObject body = iface.getValue().getAsJsonObject();
                            for (Map.Entry<String, JsonElement> field : body.entrySet())
                                if (field.getKey().startsWith("_hash"))
                                    addHash(data, field.getValue(), ifaceName);
                        }
                    }
                }

                instance = new IPCHashDatabase(data);
                Msg.info(IPCHashDatabase.class, String.format(
                    "Loaded IPC hash database with %d hashes (%d interfaces in hash collisions)",
                    instance.hashes.size(), instance.collisionInterfaces.size()));
            }
            catch (Exception e)
            {
                Msg.warn(IPCHashDatabase.class,
                    "Failed to load IPC hash database, hash matches will not be resolved: " + e.getMessage());
                instance = new IPCHashDatabase(Collections.emptyMap());
            }
        }

        return instance;
    }

    /** Record hash -> interface, de-duplicating the same interface name (it may recur under several
     *  programs/headings). A hash mapping to >1 distinct interface is a genuine collision. */
    private static void addHash(Map<String, List<String>> data, JsonElement hashEl, String ifaceName)
    {
        if (hashEl == null || !hashEl.isJsonPrimitive())
            return;

        String hash = hashEl.getAsString();
        if (hash == null || hash.isBlank())
            return;

        List<String> ifaces = data.computeIfAbsent(hash, k -> new ArrayList<>());
        if (!ifaces.contains(ifaceName))
            ifaces.add(ifaceName);
    }

    /** True if this interface shares its structural hash with another interface, so a hash match to
     *  it is ambiguous and may not be used as proof of which program a binary is. */
    public boolean isCollisionInterface(String interfaceName)
    {
        return this.collisionInterfaces.contains(interfaceName);
    }

    public HashMatch findMatch(String hash, String alternateHash)
    {
        HashMatch match = this.findMatchInMap(hash);
        if (match != null)
            return match;

        return this.findMatchInMap(alternateHash);
    }

    private HashMatch findMatchInMap(String hash)
    {
        if (hash == null)
            return null;

        List<String> interfaces = this.hashes.get(hash);

        if (interfaces == null || interfaces.isEmpty())
            return null;

        return new HashMatch(hash, interfaces, false);
    }

    public static class HashMatch
    {
        public final String hash;
        public final List<String> interfaces;
        public final boolean legacy300;
        private final String sourceOverride;

        private HashMatch(String hash, List<String> interfaces, boolean legacy300)
        {
            this(hash, interfaces, legacy300, null);
        }

        private HashMatch(String hash, List<String> interfaces, boolean legacy300, String sourceOverride)
        {
            this.hash = hash;
            this.interfaces = Collections.unmodifiableList(interfaces);
            this.legacy300 = legacy300;
            this.sourceOverride = sourceOverride;
        }

        public boolean isUnique()
        {
            return this.interfaces.size() == 1;
        }

        public String getUniqueInterface()
        {
            return this.isUnique() ? this.interfaces.get(0) : null;
        }

        public HashMatch narrowToInterface(String interfaceName, String sourceOverride)
        {
            return new HashMatch(this.hash, Collections.singletonList(interfaceName),
                this.legacy300, sourceOverride);
        }

        public String formatSource()
        {
            if (this.sourceOverride != null)
                return this.sourceOverride;

            return this.legacy300 ? "3.0.0 hash" : "hash";
        }
    }
}
