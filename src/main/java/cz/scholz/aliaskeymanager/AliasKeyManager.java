package cz.scholz.aliaskeymanager;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Created by schojak on 30.5.16.
 */
public class AliasKeyManager extends X509ExtendedKeyManager {
    X509ExtendedKeyManager original;
    String alias;

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

    public String[] getClientAliases(String s, Principal[] principals) {
        return new String[] { alias };
    }

    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return alias;
    }

    public String[] getServerAliases(String s, Principal[] principals) {
        return original.getServerAliases(s, principals);
    }

    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return original.chooseServerAlias(s, principals, socket);
    }

    public X509Certificate[] getCertificateChain(String s) {
        return original.getCertificateChain(s);
    }

    public PrivateKey getPrivateKey(String s) {
        return original.getPrivateKey(s);
    }

    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return alias;
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return original.chooseEngineServerAlias(keyType, issuers, engine);
    }
}
