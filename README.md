[![Build Status](https://travis-ci.org/scholzj/AliasKeyManager.svg?branch=master)](https://travis-ci.org/scholzj/AliasKeyManager) [![Coverage Status](https://coveralls.io/repos/github/scholzj/AliasKeyManager/badge.svg?branch=master)](https://coveralls.io/github/scholzj/AliasKeyManager?branch=master)

# AliasKeyManager

AliasKeyManager is an alternative KeyManager implementation which selects the key used for client authentication based on the alias and not based on the match against the Certification Authorities which are supported by the SSL server. It is implemented as a custom JSSE Provider, which provides only the KeyManager implementation. The AliasKeyManager extends the X509ExtendedKeyMAnager and repalces the methods used to select the client key. The methods used for selecting the server key are unchanged and their calls are forwarded to the original implementation.

## Why do we need this?

The default Java KeyManager implementation selects the client certificate (which is used for client authentication within the SSL connection) always selects the key which it will use based on the matching issuer certification authorities. The list of supported CAs is always provided by the SSL server when the SSL connection is being established. This works ok in most cases. But there are some cases when this doesn't work that well:
1) When self-signed certificates are used for authentication, they are usually not part of the CA list provided by the server (which is correct, because they are not CAs). As a result, the original KeyManager is unable to select the key to be used for authentication.
2) When there are several keys available to the client and they are all suitable for authentication, the original KeyManager selects one. But every key might have a different value (e.g. every key authenticates as different identity), it might be needed to select a specific key based on its alias.

## How is the key selected

AliasKeyManager can select the key in two different ways:
1) When the system property `cz.scholz.aliaskeymanager.alias` is specified, this will be the alias of the key which will be used
2) When the system property is not specified, the alias of the first key will be used.

This basically means, that when you have a keystore with multiple keys, you can use the system property to select the right key. When you have a keystore with only one key, you don't have to do anything, the AliasKeyManager will automatically use the key.

## Installation

There is not complicated installation process. Simply include the AliasKeyManager JAR file to the classpath.

It is also available in Maven Central repositories, so you can just add it as a Maven dependency:

```
<dependency>
    <groupId>cz.scholz</groupId>
    <artifactId>alias-key-manager</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Usage

The AliasProvider class offers several static support methods which simplify the usage of the AliasKeyManager.

### enable() / disable()

The `enable()` and `disable()` methods can be used to enable or disable the AliasKeyManager. The `enable()` method will add it to the list of JSSE providers. The `disable()` method will remove it from the list. When the AliasKeyManager is enabled, you can use it by requesting the KeyManagerFactory for algorithm `aliaskm`:
```
KeyManagerFactory kmf = KeyManagerFactory.getInstance("aliaskm");
```

**In case you have a control over the KeyManagerFactory algorithm, this is the best way how to use the AliasKeyManager. It will be used only on the places where you request the `aliaskm` algorithm. But all other places where SSL is used will continue to use Java's default implementation.**

### setAsDefault() / unSetAsDefault()

Method `setAsDefault()` will make the AliasKeyManager the default KeyManager for your application.
```
KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
```

**This allows you to use the AliasKeyManager even in clients / libraries which don't allow you to use your own algorithm. However, as a consequence, every SSL client / server which is using the default algorithm will now use the AliasKeyManager.**

Method `unSetAsDefault()` can be used to reset the default algorithm and return to the default Java implementation.