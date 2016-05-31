package cz.scholz.aliaskeymanager;

import javax.net.ssl.KeyManagerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * Implementation of JSSE provider, which provides its own KeyManager implementation.
 */
public class AliasProvider extends Provider {
    private static final String DEFAULT_ALGORITHM = KeyManagerFactory.getDefaultAlgorithm();

    private final static String ALGORITHM = "aliaskm";
    private final static Double VERSION = 1.0;
    private final static String INFO = "Alias Security provider provides the Key MAnager which selects the client key for authtentication based on the alias";
    private final String KM_SERVICE = "KeyManagerFactory.aliaskm";
    private final String KM_SPI = "cz.scholz.aliaskeymanager.AliasKeyManagerFactorySpi";

    /**
     * Constructs the JSSE Provider instance
     */
    public AliasProvider() {
        super(ALGORITHM, VERSION, INFO);
        put(KM_SERVICE, KM_SPI);
    }

    /**
     * Enabled the JSSE Provider - registers it using Security.addProvideer(...)
     */
    public static void enable()
    {
        // Add the provider
        if (Security.getProvider(ALGORITHM) == null)
        {
            Provider aliasProvider = new AliasProvider();
            Security.addProvider(aliasProvider);
        }
    }

    /**
     * Disable the JSSE Provider - if it is registered, it will be removed from the
     */
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

    /**
     * Set the AliasKeyManager as the default one for the application. In case the AliasKeyManager is not enabled, this
     * method will automatically enable it.
     */
    public static void setAsDefault()
    {
        // Make sure AliasProvider is enabled before setting it as default
        enable();

        System.setProperty("cz.scholz.aliaskeymanager.basealgorithm", DEFAULT_ALGORITHM);
        Security.setProperty("ssl.KeyManagerFactory.algorithm", ALGORITHM);
    }

    /**
     * Return to the original KeyManager implementation which was default before the AliasKeyManager
     */
    public static void unsetAsDefault()
    {
        Security.setProperty("ssl.KeyManagerFactory.algorithm", DEFAULT_ALGORITHM);
    }

    /**
     * Set the system property containing the alias of the key which should be used for authentication
     *
     * @param alias Alias of the prefered key
     */
    public static void setAlias(String alias)
    {
        System.setProperty("cz.scholz.aliaskeymanager.alias", alias);
    }

    /**
     * Clear the system property containing the alias of the key which should be used for authentication
     */
    public static void unSetAlias()
    {
        System.clearProperty("cz.scholz.aliaskeymanager.alias");
    }
}
