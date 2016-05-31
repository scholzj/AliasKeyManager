package cz.scholz.aliaskeymanager;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * AliasKeyManager extends the X509ExtendedKeyManager with a wrapper which allows to always select predefined client certificate.
 */
public class AliasKeyManager extends X509ExtendedKeyManager {
    X509ExtendedKeyManager original;
    String alias;

    /**
     * Creates an instance of AliasKeyManager based on instance of X509EntendedKeyManager.
     *
     * @param alias The key alias which should be used for cleint authentication
     * @param original The original KeyManager which should be wrapped. All functionality unrelated to the client key
     *                 selection will be taked from this KeyManager.
     */
    public AliasKeyManager(String alias, X509ExtendedKeyManager original)
    {
        if (alias == null) {
            throw new IllegalArgumentException("The alias cannot be null.");
        }

        if (original == null) {
            throw new IllegalArgumentException("The original key manager cannot be null.");
        }

        this.alias = alias;
        this.original = original;
    }

    /**
     * Returns always the selected key alias.
     *
     * @param s
     * @param principals
     * @return Key alias as a array
     */
    public String[] getClientAliases(String s, Principal[] principals) {
        return new String[] { alias };
    }

    /**
     * Returns always the selected key alias.
     *
     * @param strings
     * @param principals
     * @param socket
     * @return Key alias as a String
     */
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return alias;
    }

    /**
     * Falls back to the original KeyManager.
     *
     * @param s
     * @param principals
     * @return
     */
    public String[] getServerAliases(String s, Principal[] principals) {
        return original.getServerAliases(s, principals);
    }

    /**
     * Falls back to the original KeyManager.
     *
     * @param s
     * @param principals
     * @param socket
     * @return
     */
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return original.chooseServerAlias(s, principals, socket);
    }

    /**
     * Falls back to the original KeyManager.
     *
     * @param s
     * @return
     */
    public X509Certificate[] getCertificateChain(String s) {
        return original.getCertificateChain(s);
    }

    public PrivateKey getPrivateKey(String s) {
        return original.getPrivateKey(s);
    }

    /**
     * Returns always the selected key alias.
     *
     * @param keyType
     * @param issuers
     * @param engine
     * @return Key alias as a String
     */
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return alias;
    }

    /**
     * Falls back to the original KeyManager.
     *
     * @param keyType
     * @param issuers
     * @param engine
     * @return
     */
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return original.chooseEngineServerAlias(keyType, issuers, engine);
    }
}
