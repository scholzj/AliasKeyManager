package cz.scholz.aliaskeymanager;

import javax.net.ssl.KeyManagerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * Created by schojak on 30.5.16.
 */
public class AliasProvider extends Provider {
    private static final String DEFAULT_ALGORITHM = KeyManagerFactory.getDefaultAlgorithm();

    private final static String ALGORITHM = "aliaskm";
    private final static Double VERSION = 1.0;
    private final static String INFO = "Alias Security provider provides the Key MAnager which selects the client key for authtentication based on the alias";
    private final String KM_SERVICE = "KeyManagerFactory.aliaskm";
    private final String KM_SPI = "cz.scholz.aliaskeymanager.AliasKeyManagerFactorySpi";

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     */
    public AliasProvider() {
        super(ALGORITHM, VERSION, INFO);
        put(KM_SERVICE, KM_SPI);
    }

    public static void enable()
    {
        // Add the provider
        if (Security.getProvider(ALGORITHM) == null)
        {
            Provider aliasProvider = new AliasProvider();
            Security.addProvider(aliasProvider);
        }
    }

    public static void disable()
    {
        // If our algo is the default, return the original default
        if (ALGORITHM.equals(Security.getProperty("ssl.KeyManagerFactory.algorithm")))
        {
            Security.setProperty("ssl.KeyManagerFactory.algorithm", DEFAULT_ALGORITHM);
        }

        // Remove the provider
        if (Security.getProvider(ALGORITHM) != null)
        {
            Security.removeProvider(ALGORITHM);
        }
    }

    public static void setAsDefault()
    {
        // Make sure AliasProvidert is enabled
        enable();

        // Set AliasProvider as default and the original default as base
        System.setProperty("cz.scholz.aliaskeymanager.basealgorithm", DEFAULT_ALGORITHM);
        Security.setProperty("ssl.KeyManagerFactory.algorithm", ALGORITHM);
    }

    public static void unsetAsDefault()
    {
        // Set the original default algo to be default again
        Security.setProperty("ssl.KeyManagerFactory.algorithm", DEFAULT_ALGORITHM);
    }

    public static void setAlias(String alias)
    {
        // Sets the system property with the alias
        System.setProperty("cz.scholz.aliaskeymanager.alias", alias);
    }

    public static void unSetAlias()
    {
        // Clears the system property with the alias
        System.clearProperty("cz.scholz.aliaskeymanager.alias");
    }
}
