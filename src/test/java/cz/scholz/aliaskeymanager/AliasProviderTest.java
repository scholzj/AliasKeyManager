package cz.scholz.aliaskeymanager;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.Security;

/**
 * Created by schojak on 31.5.16.
 */
public class AliasProviderTest {
    @Test
    public void testSetAlias()
    {
        AliasProvider.setAlias("myAlias");
        Assert.assertEquals(System.getProperty("cz.scholz.aliaskeymanager.alias"), "myAlias", "System property was not properly set");
        AliasProvider.unSetAlias();
        Assert.assertNotEquals(System.getProperty("cz.scholz.aliaskeymanager.alias"), "myAlias", "System property was not properly cleared");
    }

    @Test
    public void testEnableProvider()
    {
        AliasProvider.enable();
        Assert.assertNotNull(Security.getProvider("aliaskm"), "The provide doesn't seem to exist");

        AliasProvider.disable();
        Assert.assertNull(Security.getProvider("aliaskm"), "The provide doesn't seem to be disabled");
    }

    @Test
    public void testSetAsDefaultProvider()
    {
        AliasProvider.setAsDefault();
        Assert.assertEquals(Security.getProperty("ssl.KeyManagerFactory.algorithm"), "aliaskm", "The new key manager has been set as default");

        AliasProvider.unsetAsDefault();
        Assert.assertNotEquals(Security.getProperty("ssl.KeyManagerFactory.algorithm"), "aliaskm", "The new key manager is still the default");
    }
}
