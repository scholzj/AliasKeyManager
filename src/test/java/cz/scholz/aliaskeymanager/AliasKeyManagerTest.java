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
    public void testClientAliasFunctions() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(AliasKeyManagerTest.class.getResourceAsStream(keystorePath), keystorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword.toCharArray());

        KeyManager[] km = kmf.getKeyManagers();

        for (int i = 0; i < km.length; i++) {
            if (km[i] instanceof X509ExtendedKeyManager) {
                AliasKeyManager myKeyManager = new AliasKeyManager(alias, (X509ExtendedKeyManager)km[i]);
                Assert.assertEquals(myKeyManager.chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match 1");
                Assert.assertEquals(myKeyManager.chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match 2");
                Assert.assertEquals(myKeyManager.getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match 3");
            }
        }
    }

    @Test
    public void testWrapping() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(AliasKeyManagerTest.class.getResourceAsStream(keystorePath), keystorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword.toCharArray());

        KeyManager[] km = kmf.getKeyManagers();

        for (int i = 0; i < km.length; i++) {
            if (km[i] instanceof X509ExtendedKeyManager) {
                AliasKeyManager myKeyManager = new AliasKeyManager(alias, (X509ExtendedKeyManager)km[i]);
                // Test the server calls from the wrapped KM against the unwrapped KM
                Assert.assertEquals(myKeyManager.chooseServerAlias("", new Principal[0], new Socket()), ((X509ExtendedKeyManager)km[i]).chooseServerAlias("", new Principal[0], new Socket()), "Aliases do not match 4");
                Assert.assertEquals(myKeyManager.chooseEngineServerAlias("", new Principal[0], SSLContext.getDefault().createSSLEngine()), ((X509ExtendedKeyManager)km[i]).chooseEngineServerAlias("", new Principal[0], SSLContext.getDefault().createSSLEngine()), "Aliases do not match 5");
                Assert.assertEquals(myKeyManager.getServerAliases("", new Principal[0]), ((X509ExtendedKeyManager)km[i]).getServerAliases("", new Principal[0]), "Aliases do not match 6");
                Assert.assertEquals(myKeyManager.getCertificateChain(alias), ((X509ExtendedKeyManager)km[i]).getCertificateChain(alias), "Aliases do not match 7");
                Assert.assertEquals(myKeyManager.getPrivateKey(alias), ((X509ExtendedKeyManager)km[i]).getPrivateKey(alias), "Aliases do not match 8");
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testNullAlias() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(AliasKeyManagerTest.class.getResourceAsStream(keystorePath), keystorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword.toCharArray());

        KeyManager[] km = kmf.getKeyManagers();

        for (int i = 0; i < km.length; i++) {
            if (km[i] instanceof X509ExtendedKeyManager) {
                AliasKeyManager myKeyManager = new AliasKeyManager(null, (X509ExtendedKeyManager)km[i]);
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testNullKeyManager() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        AliasKeyManager myKeyManager = new AliasKeyManager(alias, null);
    }
}
