package cz.scholz.aliaskeymanager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;

import org.testng.Assert;
import org.testng.annotations.*;

import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Created by schojak on 30.5.16.
 */
public class AliasKeyManagerFactorySpiTest {
    protected final String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

    protected String keystorePath = "/test-keystore.jks";
    protected String keystorePathMulti = "/test-multikey-keystore.jks";
    protected String keystorePathEmpty = "/test-empty-keystore.jks";
    protected String keystorePassword = "123456";
    protected String alias = "myalias";

    @Test
    public void TestKeyManagerInstances() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyManagerFactory kmf = prepareKeyManagerFactory();
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            if (!(managers[i] instanceof AliasKeyManager))
            {
                Assert.fail("KeyManager is not instance of AliasKeyManager " + managers[i].toString());
            }
        }
    }

    @Test
    public void TestAliasFromSystemProperty() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        System.setProperty("cz.scholz.aliaskeymanager.alias", alias);

        KeyManagerFactory kmf = prepareKeyManagerFactory();
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match");
        }
    }

    @Test
    public void TestAliasWithoutProperty() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyManagerFactory kmf = prepareKeyManagerFactory();
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match");
        }
    }

    @Test
    public void TestAliasWithPropertyMultikeyKeystore() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        System.setProperty("cz.scholz.aliaskeymanager.alias", "myAlias2");

        KeyManagerFactory kmf = prepareKeyManagerFactory("aliaskm", keystorePathMulti);
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseClientAlias(new String[0], new Principal[0], new Socket()), "myAlias2", "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), "myAlias2", "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).getClientAliases("", new Principal[0]), new String[] { "myAlias2" }, "Aliases do not match");
        }
    }

    @Test
    public void TestAliasWithoutPropertyMultikeyKeystore() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyManagerFactory kmf = prepareKeyManagerFactory("aliaskm", keystorePathMulti);
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match");
        }
    }

    @Test(expectedExceptions = KeyStoreException.class)
    public void TestEmptyKeystore() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyManagerFactory kmf = prepareKeyManagerFactory("aliaskm", keystorePathEmpty);
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match");
        }
    }

    @Test(expectedExceptions = KeyStoreException.class)
    public void TestWrongAliasFromSystemProperty() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        System.setProperty("cz.scholz.aliaskeymanager.alias", "someOtherAlias");

        KeyManagerFactory kmf = prepareKeyManagerFactory();
        KeyManager[] managers = kmf.getKeyManagers();

        for (int i = 0; i < managers.length; i++)
        {
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseClientAlias(new String[0], new Principal[0], new Socket()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).chooseEngineClientAlias(new String[0], new Principal[0], SSLContext.getDefault().createSSLEngine()), alias, "Aliases do not match");
            Assert.assertEquals(((X509ExtendedKeyManager)managers[i]).getClientAliases("", new Principal[0]), new String[] { alias }, "Aliases do not match");
        }
    }

    @Test(expectedExceptions = NoSuchAlgorithmException.class)
    public void TestFactoryDefaultAlgorithmWithoutBase() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        Security.setProperty("ssl.KeyManagerFactory.algorithm", "aliaskm");
        KeyManagerFactory kmf = prepareKeyManagerFactoryWithDefaultAlgo();
    }

    @Test
    public void TestFactoryDefaultAlgorithmWithBase() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        AliasProvider.setAsDefault();
        KeyManagerFactory kmf = prepareKeyManagerFactoryWithDefaultAlgo();
    }

    @Test(expectedExceptions = NoSuchAlgorithmException.class)
    public void TestFactoryDefaultAlgorithmWithWrongBase() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        System.setProperty("cz.scholz.aliaskeymanager.basealgorithm", "MySuperSpecialAlgo");
        Security.setProperty("ssl.KeyManagerFactory.algorithm", "aliaskm");
        KeyManagerFactory kmf = prepareKeyManagerFactoryWithDefaultAlgo();
    }

    @Test(expectedExceptions = NoSuchAlgorithmException.class)
    public void TestFactoryDefaultAlgorithmWithEqualBase() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        System.setProperty("cz.scholz.aliaskeymanager.basealgorithm", "aliaskm");
        Security.setProperty("ssl.KeyManagerFactory.algorithm", "aliaskm");
        KeyManagerFactory kmf = prepareKeyManagerFactoryWithDefaultAlgo();
    }

    @BeforeMethod
    public void setUp()
    {
        AliasProvider.enable();
    }

    @AfterMethod
    public void tearDown()
    {
        System.clearProperty("cz.scholz.aliaskeymanager.alias");
        System.clearProperty("cz.scholz.aliaskeymanager.basealgorithm");
        AliasProvider.disable();
    }

    private KeyManagerFactory prepareKeyManagerFactoryWithDefaultAlgo() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException
    {
        return prepareKeyManagerFactory(KeyManagerFactory.getDefaultAlgorithm());
    }

    private KeyManagerFactory prepareKeyManagerFactory() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException
    {
        return prepareKeyManagerFactory("aliaskm");
    }

    private KeyManagerFactory prepareKeyManagerFactory(String algorithm) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException
    {
        return prepareKeyManagerFactory(algorithm, keystorePath);
    }

    private KeyManagerFactory prepareKeyManagerFactory(String algorithm, String keyStore) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException
    {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(AliasKeyManagerTest.class.getResourceAsStream(keyStore), keystorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, keystorePassword.toCharArray());

        return kmf;
    }
}
