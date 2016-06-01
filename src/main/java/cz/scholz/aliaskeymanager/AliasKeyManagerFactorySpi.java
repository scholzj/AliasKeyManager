package cz.scholz.aliaskeymanager;

import javax.net.ssl.*;

import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * AliasKeyManagerFactorySpi is used by Java's KeyManagerFactory to create the KeyManmager instances. This class
 * contains the initialization of the KeyManager based on the base algorithm.
 */
public class AliasKeyManagerFactorySpi extends KeyManagerFactorySpi {
    protected final String algorithm = "aliaskm";
    protected String baseAlgorithm;
    protected KeyManagerFactory originalFactory;
    protected String alias;

    /**
     * Initializes the KeyManagerFactory with the keystore and its password. This class creates an instance of the
     * KeyManagerFactory created using the base algorithm / default algorithm and determines the key alias which should
     * be used.
     *
     * @param keyStore Keystore containing the private key
     * @param chars Password to access the keyStore
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    protected void engineInit(KeyStore keyStore, char[] chars) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (KeyManagerFactory.getDefaultAlgorithm().equals(algorithm))
        {
            baseAlgorithm = System.getProperty("cz.scholz.aliaskeymanager.basealgorithm");

            if (algorithm.equals(baseAlgorithm))
            {
                throw new NoSuchAlgorithmException("Base algorithm has to be different from " + algorithm);
            }
        }
        else
        {
            baseAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        }

        if (baseAlgorithm == null)
        {
            throw new NoSuchAlgorithmException("No base algorithm has been identified");
        }

        originalFactory = KeyManagerFactory.getInstance(baseAlgorithm);
        originalFactory.init(keyStore, chars);

        alias = determineAlias(keyStore, chars);
    }

    /**
     * Currently not implemented.
     *
     * @param managerFactoryParameters ManagerFactoryParameters object containing the parametrs of the KeyManagerFactory.
     * @throws InvalidAlgorithmParameterException
     */
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Unsupported ManagaerFactoryParameters");
    }

    /**
     * Return the array with wrapped KeyManager instances.
     *
     * @return Array of KeyManager instances
     */
    protected KeyManager[] engineGetKeyManagers() {
        return wrapKeyManagers(originalFactory.getKeyManagers());
    }

    /**
     * Wraps the KeyManager instances provided by the default KeyManager into the AliasKeyManager.
     *
     * @param originalKeyManagers The KeyMAnager instances as returned by the default algorithm
     * @return Array of wrapped KeyManager instances
     */
    protected KeyManager[] wrapKeyManagers(KeyManager[] originalKeyManagers)
    {
        List<KeyManager> wrapped = new ArrayList<KeyManager>();

        for (int i = 0; i < originalKeyManagers.length; i++) {
            if (originalKeyManagers[i] instanceof X509ExtendedKeyManager) {
                KeyManager wrap = new AliasKeyManager(alias, (X509ExtendedKeyManager) originalKeyManagers[i]);
                wrapped.add(wrap);
            }
        }

        return wrapped.toArray(new KeyManager[0]);
    }

    /**
     * Determines and validates the alias which should be used for the authentication. The alias is either taken from
     * the System property or from the KeyStore.
     *
     * @param keyStore Keystore containing the private key
     * @param chars Password to access the keyStore
     * @return Alias of the key which should be used
     * @throws KeyStoreException
     */
    protected String determineAlias(KeyStore keyStore, char[] chars) throws KeyStoreException {
        String alias = System.getProperty("cz.scholz.aliaskeymanager.alias");

        if (alias != null)
        {
            if (keyStore.containsAlias(alias)) {
                return alias;
            }
            else
            {
                throw new KeyStoreException("Alias " + alias + " does not exist in the keystore");
            }
        }

        else
        {
            Enumeration<String> aliases = keyStore.aliases();

            if (aliases.hasMoreElements())
            {
                return aliases.nextElement();
            }
            else
            {
                throw new KeyStoreException("No aliases found in the keystore");
            }
        }
    }
}
