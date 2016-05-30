package cz.scholz.aliaskeymanager;

import javax.net.ssl.*;

import org.testng.Assert;
import org.testng.annotations.Test;
import sun.security.ssl.SSLEngineImpl;

import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Created by schojak on 30.5.16.
 */
public class AliasKeyManagerTest {
    protected String keystorePath = "/test-keystore.jks";
    protected String keystorePassword = "123456";
    protected String alias = "myalias";

    @Test
    public void testChooseClientAlias() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(AliasKeyManagerTest.class.getResourceAsStream(keystorePath), keystorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword.toCharArray());

        KeyManager[] km = kmf.getKeyManagers();

        for (int i = 0; i < km.length; i++) {
            if (km[i] instanceof X509ExtendedKeyManager) {
                AliasKeyManager myKeyManager = new AliasKeyManager(alias, (X509ExtendedKeyManager)km[i]);
                Assert.assertEquals(myKeyManager.chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match");
                Assert.assertEquals(myKeyManager.chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match");
                Assert.assertEquals(myKeyManager.getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match");
            }
        }
    }
}
