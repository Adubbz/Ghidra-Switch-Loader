package adubbz.nx.analyzer.ipc;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ghidra.util.Msg;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Known HIPC sm service-port names (e.g. "fsp-srv", "set:sys"), loaded from
 * {@code /ipc_services.json}.  Used to recover, robustly and symbol-independently, which services
 * a module connects to as a client: a referenced service-name string that is in this set is a
 * connection.  This is factual reference data (documented sm port names), not inference, and is
 * extendable by observing more modules.
 */
public class IPCServiceDatabase
{
    private final Set<String> services;

    private static IPCServiceDatabase instance;

    private IPCServiceDatabase(Set<String> services)
    {
        this.services = services;
    }

    public static IPCServiceDatabase getInstance()
    {
        if (instance == null)
        {
            try (InputStream is = IPCServiceDatabase.class.getResourceAsStream("/ipc_services.json");
                 InputStreamReader reader = new InputStreamReader(is))
            {
                Type type = new TypeToken<List<String>>(){}.getType();
                List<String> list = new Gson().fromJson(reader, type);
                instance = new IPCServiceDatabase(list != null ? new HashSet<>(list) : Collections.emptySet());
                Msg.info(IPCServiceDatabase.class,
                    String.format("Loaded %d known HIPC service names", instance.services.size()));
            }
            catch (Exception e)
            {
                Msg.warn(IPCServiceDatabase.class,
                    "Failed to load HIPC service list, service imports will not be recovered: " + e.getMessage());
                instance = new IPCServiceDatabase(Collections.emptySet());
            }
        }

        return instance;
    }

    public boolean isKnownService(String name)
    {
        return this.services.contains(name);
    }

    public boolean isEmpty()
    {
        return this.services.isEmpty();
    }
}
