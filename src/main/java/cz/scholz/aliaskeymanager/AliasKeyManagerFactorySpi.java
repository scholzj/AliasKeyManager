package cz.scholz.aliaskeymanager;

import javax.net.ssl.*;

import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Created by schojak on 30.5.16.
 */
public class AliasKeyManagerFactorySpi extends KeyManagerFactorySpi {
    protected final String algorithm = "aliaskm";
    protected String baseAlgorithm;
    protected KeyManagerFactory originalFactory;
    protected String alias;

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

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        // Do nothing
    }

    protected KeyManager[] engineGetKeyManagers() {
        return wrapKeyManagers(originalFactory.getKeyManagers());
    }

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
