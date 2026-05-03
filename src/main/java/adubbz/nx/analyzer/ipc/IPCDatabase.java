package adubbz.nx.analyzer.ipc;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ghidra.util.Msg;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.Map;

public class IPCDatabase
{
    // Outer key: demangled interface name (e.g. "nn::fssrv::sf::IFileSystemProxy")
    // Inner key: command id (as string for JSON compat)
    // Value: command name (e.g. "OpenFileSystemWithId")
    private final Map<String, Map<String, String>> db;

    private static IPCDatabase instance;

    private IPCDatabase(Map<String, Map<String, String>> db)
    {
        this.db = db;
    }

    public static IPCDatabase getInstance()
    {
        if (instance == null)
        {
            try (InputStream is = IPCDatabase.class.getResourceAsStream("/ipc_database.json");
                 InputStreamReader reader = new InputStreamReader(is))
            {
                Type type = new TypeToken<Map<String, Map<String, String>>>(){}.getType();
                Map<String, Map<String, String>> data = new Gson().fromJson(reader, type);
                instance = new IPCDatabase(data);
                Msg.info(IPCDatabase.class, String.format("Loaded IPC database with %d interfaces", data.size()));
            }
            catch (Exception e)
            {
                Msg.warn(IPCDatabase.class, "Failed to load IPC database, command names will not be resolved: " + e.getMessage());
                instance = new IPCDatabase(Collections.emptyMap());
            }
        }
        return instance;
    }

    /**
     * Looks up a command name for a given interface and command ID.
     * The interface name is matched by checking if it ends with any known key,
     * to handle both full demangled names and shortened ones.
     *
     * @param interfaceName The demangled vtable name (with or without ::vtable suffix)
     * @param cmdId The command ID
     * @return The command name, or null if not found
     */
    public String getCommandName(String interfaceName, long cmdId)
    {
        String iface = interfaceName.replace("::vtable", "").trim();
        String cmdKey = String.valueOf(cmdId);

        Msg.debug(this, String.format("getCommandName: looking up iface='%s' cmd=%s", iface, cmdKey));

        // Exact match first
        Map<String, String> cmds = db.get(iface);
        if (cmds != null)
        {
            String result = cmds.get(cmdKey);
            Msg.debug(this, String.format("  exact match found, cmd result: %s", result));
            return result;
        }

        // Suffix match
        for (Map.Entry<String, Map<String, String>> entry : db.entrySet())
        {
            if (entry.getKey().endsWith("::" + iface) || entry.getKey().equals(iface))
            {
                String result = entry.getValue().get(cmdKey);
                Msg.debug(this, String.format("  suffix match on '%s', cmd result: %s", entry.getKey(), result));
                return result;
            }
        }

        Msg.debug(this, "  no match found");
        return null;
    }
    public Map<String, Map<String, String>> getAllInterfaces()
    {
        return Collections.unmodifiableMap(db);
    }
}