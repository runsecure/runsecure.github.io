---
title: Getting started with Java
sidebar_label: Java
sidebar_position: 5
description: Use HkdfGuard from Java and Spring Boot to encrypt data and configuration secrets under a TPM- or Secure Enclave-protected key.
---

# Getting started with Java

This guide takes a Java application from nothing to encrypting and decrypting data under a key the
platform protects. It first checks the setup with an in-memory key. Then it moves to a durable
key file, encrypts configuration secrets in a deployment pipeline, and reads them back, with or
without Spring Boot.

`hkdfguard-java` reads and writes the same values as every other port.

## Before you start

You need:

- **Java 25** for the native key wrapper, which calls the native library through the Foreign
  Function & Memory API. The other modules need only Java 21, so on Java 21 you can use them with
  a key wrapper of your own, such as a cloud KMS.
- **The HkdfGuard native library, installed on the machine, with a service provisioned.** Follow
  the guide for your OS first: [Windows](windows.md), [macOS](macos.md) or [Linux](linux.md).
  This guide uses the service name `com.example.myapp`.
- **An account that may use the key.** Your application must run as an account the service's
  key allows:
  - Windows: a member of `HkdfGuardUsers`.
  - Linux: in `tss` and `hkdfguard`.
  - macOS (user-scoped): the user who provisioned it.

The Java library loads the native library only from its install location, after checking the
location, its ownership and the library's signature. On Linux it also checks the dynamic linker's
environment. There is no fallback and no override.

## 1. Add the dependencies

Every module uses the group `io.github.runsecure`:

| Artifact | What it gives you |
|---|---|
| `hkdfguard-dataencryptionkey` | `KeyRingImpl`, `KeyRingBuilder`, data protectors and the `enc::v1::...` format |
| `hkdfguard-cryptoprovider-aesgcm256` | The AES-256-GCM cipher, and `AesGcmPipelineDataProtectorImpl` for pipelines |
| `hkdfguard-keywrapping-v1` | `NativeHkdfKeyWrapperV1Impl`, which calls the native library (Java 25) |
| `hkdfguard-options` | `HkdfGuardOptions`, to configure the ring from settings |
| `hkdfguard-cache` | `ProtectedCacheImpl`, an in-memory cache that holds only ciphertext |
| `hkdfguard-spring-boot-starter` | Spring Boot 4 auto-configuration, `ProtectedEnvironment` and a health indicator |

```xml
<properties>
  <hkdfguard.version><!-- the release you use --></hkdfguard.version>
</properties>

<dependencies>
  <dependency>
    <groupId>io.github.runsecure</groupId>
    <artifactId>hkdfguard-dataencryptionkey</artifactId>
    <version>${hkdfguard.version}</version>
  </dependency>
  <dependency>
    <groupId>io.github.runsecure</groupId>
    <artifactId>hkdfguard-cryptoprovider-aesgcm256</artifactId>
    <version>${hkdfguard.version}</version>
  </dependency>
  <dependency>
    <groupId>io.github.runsecure</groupId>
    <artifactId>hkdfguard-keywrapping-v1</artifactId>
    <version>${hkdfguard.version}</version>
  </dependency>
</dependencies>
```

:::note Where the modules come from
Releases are published on the
[GitHub Releases page](https://github.com/runsecure/hkdfguard-java/releases): each module's jar,
sources and javadoc jars and POM, with GPG signatures and build provenance. They are published to
Maven Central once the project turns that on. Until then, install the modules you use, and the
parent POM, into your local Maven repository:

```sh
V=0.9.0   # the release you downloaded
gh release download "v$V" --repo runsecure/hkdfguard-java --pattern '*.jar' --pattern '*.pom'
gh attestation verify "hkdfguard-dataencryptionkey-$V.jar" --repo runsecure/hkdfguard-java   # repeat for each file

mvn install:install-file -Dfile="hkdfguard-parent-$V.pom" -DpomFile="hkdfguard-parent-$V.pom" -Dpackaging=pom
for module in diagnostics abstractions dataencryptionkey cryptoprovider-aesgcm256 keywrapping-v1; do
    mvn install:install-file -Dfile="hkdfguard-$module-$V.jar" -DpomFile="hkdfguard-$module-$V.pom"
done
```

Add `options`, `cache` or `spring-boot-starter` to the list if you use them.
:::

The native key wrapper uses a restricted Java API, so start the JVM with native access enabled:

```sh
java --enable-native-access=ALL-UNNAMED -jar myapp.jar
```

On the module path, use `--enable-native-access=io.github.runsecure.hkdfguard.keywrapping.v1`
instead.

## 2. Check the setup with an in-memory key

```java
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Demo {
    public static void main(String[] args) {
        try (var ring = new KeyRingBuilder()
                .withServiceName("com.example.myapp")
                .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl("com.example.myapp"))
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyRefreshInterval(60)
                .withEphemeralKey(1)
                .buildAsync()
                .join()) {

            var formats = new DefaultFormatProviderImpl();
            byte[] aad = "customer-notes".getBytes(StandardCharsets.UTF_8); // what the value is for

            // Encrypt under the current key. encrypt zeroes the plaintext it is given.
            var current = ring.getCurrent();
            byte[] ciphertext = current.key().encrypt("The launch code is 0000".getBytes(StandardCharsets.UTF_8), aad);
            String stored = formats.format(new KeyTrackingValue(current.version(), ciphertext));
            System.out.println(stored);

            // Decrypt with the key for the value's own version.
            KeyTrackingValue parsed = formats.parse(stored);
            DataEncryptionKey dek = ring.get(parsed.keyVersion());
            byte[] result = new byte[parsed.value().length];
            try {
                int length = dek.decrypt(parsed.value(), aad, result);
                System.out.println(new String(result, 0, length, StandardCharsets.UTF_8)); // a String for the demo only
            } finally {
                Arrays.fill(result, (byte) 0);
            }
        }
    }
}
```

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `buildAsync` asked the native library to generate a DEK and wrap it under your service's key, then
  unwrapped it into memory that is zeroed when the ring closes. The plaintext DEK never touched
  disk.
- `ring.getCurrent()` returns the **current version** and its **data encryption key**.
  `DataEncryptionKey.encrypt` seals the bytes with AES-256-GCM under that key, bound to the AAD, and
  zeroes the plaintext it was given.
- `DefaultFormatProviderImpl.format` turns the version and the ciphertext into the stored form,
  `enc::v1::...`: `v1` is the key version, and the rest is the ciphertext in base64. However you
  store a value, keep its version with it.
- To decrypt, `ring.get(version)` returns the key **for the value's own version**, not the current
  one, so a value encrypted before a rotation still decrypts. A result buffer as long as the
  ciphertext always fits the plaintext.
- The **AAD** says what the value is for. It is bound into the ciphertext, so decrypting with
  different AAD fails authentication: a value encrypted for one purpose never decrypts as another.
- `withKeyRefreshInterval(60)` re-checks the key every 60 seconds. If it stops being available,
  encryption and decryption stop after three failed checks, until access returns.

Async methods return a `CompletableFuture`. Argument errors throw from the call itself, and a
failure revealing a key completes the future exceptionally.

:::tip The shortcut: data protectors
`ring.createProtector("customer-notes")` does these same steps for text values: it takes the current
key, uses the UTF-8 of its name as the AAD, and formats the result. Values are interchangeable: a
protector named `customer-notes` decrypts the value above, and the reverse.
:::

On macOS, the first run shows a keychain prompt for `java`: choose **Always Allow**. That approval
covers every program that `java` runs as that user. See
[the first unwrap asks for permission](macos.md#the-first-unwrap-asks-for-permission) for how to
narrow it in production.

An **ephemeral key** lives only as long as the process, which suits short-lived data. Data you
store needs a key file.

## 3. Use a key file

In a deployment, a deployer wraps each release's DEK into a **key file** with `hkdfguard wrap`, as
the OS guides show. Your application registers it by version:

```java
var ring = new KeyRingBuilder()
        .withServiceName("com.example.myapp")
        .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl("com.example.myapp"))
        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
        .withKeyRefreshInterval(60)
        .withKeyFile(1, "/etc/myapp/keys/myapp.v1.key")
        .buildAsync()
        .join();
```

Use the path your OS guide prepared:

| OS | Example key file |
|---|---|
| Windows | `C:\HkdfGuardKeys\myapp\myapp.v1.key` (never under `C:\ProgramData`) |
| Linux | `/etc/myapp/keys/myapp.v1.key` |
| macOS | `~/Library/Application Support/MyApp/keys/myapp.v1.key`, or a root-owned folder in production |

The key file is read through the native library. A refusal is an `IOException` naming the path
and the status:

- `NoSuchFileException` (-32);
- `AccessDeniedException` (-33, or -39 for an untrusted location);
- `InvalidKeyFileException` (-35 to -38).

**To rotate,** wrap a new DEK as `myapp.v2.key` and add `.withKeyFile(2, ...)`. New values use the
highest version. Older values still decrypt for as long as their key file stays registered.

**Mixing key files and ephemeral keys.** A ring can hold both. Ephemeral keys rotate (every 24
hours by default), and each rotation adds a key at the current version + 1. So give the ephemeral
key a version above every key file, or turn ephemeral rotation off. Otherwise the first rotation
would replace the key file as the current key, and values encrypted after it would be lost on a
restart. The builder refuses such a ring.

## 4. Encrypt configuration secrets in your pipeline

Your release pipeline creates the DEK and encrypts the application's secrets under it. Then, on
the target machine, it hands the same DEK to `hkdfguard wrap`. Each secret is bound to the
configuration key it is stored under, so a value moved to another key fails to decrypt:

```java
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 1)) {
    // Encrypt each secret for the property it will be stored under.
    String password = pipeline.encrypt("s3cret", "spring.datasource.password");
    // ...write "enc::v1::..." into application.yml as spring.datasource.password...

    // On the target machine, wrap the same key into the release's key file.
    var tool = new ProcessBuilder(List.of(toolPath, "wrap",
            "--service-name", "com.example.myapp", "--key-file-path", keyFilePath, "--dek-stdin"))
            // Add "--group", "<the service's group>" so the application can read it.
            .redirectOutput(ProcessBuilder.Redirect.INHERIT)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start();

    var ascii = StandardCharsets.US_ASCII.encode(pipeline.getKeyAsBase64().duplicate());
    try (var stdin = tool.getOutputStream()) {
        stdin.write(ascii.array(), ascii.arrayOffset() + ascii.position(), ascii.remaining());
    } finally {
        Arrays.fill(ascii.array(), (byte) 0);
    }
    if (tool.waitFor() != 0) {
        throw new IllegalStateException("hkdfguard wrap failed with exit code " + tool.exitValue());
    }
}
```

`toolPath` is `C:\Program Files\HkdfGuard\v1\hkdfguard.exe` on Windows, `/usr/bin/hkdfguard` on
Linux, and `/usr/local/bin/hkdfguard` on macOS. Run this step as a deployer, as your OS guide
describes.

:::warning
Pass the DEK only on standard input, as above. Never pass it as a command-line argument or an
environment variable, and never turn `getKeyAsBase64()` into a `String`: strings can't be cleared
from memory. Closing the pipeline protector zeroes the key.
:::

## 5. Read the secrets back

Each configuration value is an `enc::v1::...` string, encrypted for the property it is stored
under. Parse it, take the key for its version, and decrypt it with that property's AAD:

```java
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;

String encrypted = environment.getProperty("spring.datasource.password"); // "enc::v1::..."
KeyTrackingValue value = new DefaultFormatProviderImpl().parse(encrypted);
DataEncryptionKey dek = ring.get(value.keyVersion());

byte[] result = new byte[value.value().length];
try {
    int length = dek.decrypt(value.value(), ProtectedConfigurationPurpose.aadFor("spring.datasource.password"), result);
    // use result[0..length), the UTF-8 bytes of the secret
} finally {
    Arrays.fill(result, (byte) 0);
}
```

`ProtectedConfigurationPurpose.aadFor` gives the AAD the pipeline bound the value to. A value
copied to a different property fails authentication. Encrypt and read each value under the same
name: for Spring, its canonical form, such as `my-service.api-key`. The key ring must have the
release's key file registered at the version the pipeline used, here `1`.

### With Spring Boot

Add `hkdfguard-spring-boot-starter` (Spring Boot 4.1), and configure the ring under `hkdfguard`:

```yaml
hkdfguard:
  service-name: com.example.myapp
  key-refresh-interval: 60
  key-files:
    - version: 1
      path: /etc/myapp/keys/myapp.v1.key
```

The starter builds the ring at startup when `hkdfguard.service-name` is set, and closes it with the
context. Invalid settings, or a misspelt property under `hkdfguard`, fail startup with every
problem listed.

**The shortcut: `ProtectedEnvironment`.** Inject it, and it does the steps above for any property
source. `@Value` and `getProperty` still return the ciphertext; `decrypt` reads the property fresh
on every call:

```java
var maxLength = protectedEnvironment.findMaxDecryptedLength("spring.datasource.password").orElseThrow();
var password = new char[maxLength];
try {
    var length = protectedEnvironment.decrypt("spring.datasource.password", password);
    // use password[0..length)
} finally {
    Arrays.fill(password, '\0');
}
```

Encrypt each value for the property name in Spring's canonical form,
`my-service.api-key`, which is the name it is read by.

With Actuator, `/actuator/health` gains an `hkdfguard` component. It reports `DOWN` when the
current key can't protect new values.

### Without Spring

To describe the ring in a settings file, `HkdfGuardOptions.fromMap` reads a parsed section,
including a .NET `appsettings.json` `HkdfGuard` section unchanged. `requireValid()` reports every
problem at once:

```java
var options = HkdfGuardOptions.fromMap(settings).requireValid();
var ring = options.applyTo(new KeyRingBuilder())
        .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(options.getServiceName()))
        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
        .buildAsync()
        .join();
```

## 6. Harden the process

DEKs pass through your process's memory. Opt in to process hardening first thing in `main`, before
starting a framework, so crash dumps and other processes of the same user can't read it:

```java
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeProcessHardening;
import io.github.runsecure.hkdfguard.keywrapping.v1.ProcessHardeningOption;

public static void main(String[] args) {
    NativeProcessHardening.apply(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE); // Windows services
    // NativeProcessHardening.apply();                                               // elsewhere
    SpringApplication.run(MyApplication.class, args);
}
```

It throws `IllegalStateException` if it fails; don't start without it. On Windows, use
`REQUIRE_PROTECTED_SIGNATURE`: the JVM starts threads before `main`, and the strict form also
closes the threads it starts later. The Spring Boot starter deliberately has no property for
this, since auto-configuration runs too late. Debuggers, `jcmd` and `jstack` stop working for the
process.

[Process hardening](../processhardening.md) explains what each platform does, and when to
pass the flag.

## Troubleshooting

Every native error message names the status and what it means.

| You see | Cause | Fix |
|---|---|---|
| `NativeLibraryNotFoundException` | The native library isn't installed | Follow your OS guide's install step |
| `SecurityException` | The installed library, a folder above it, or the dynamic linker's environment failed verification | Reinstall the native package; clear `LD_LIBRARY_PATH` and `LD_PRELOAD` |
| `IllegalCallerException` or a warning about restricted methods | Native access isn't enabled | Start the JVM with `--enable-native-access` |
| `CryptographicException`, status -17 | No key is provisioned for this service name | Provision it, with the same service name |
| `CryptographicException`, status -18 | The key exists, but this account may not use it | Windows: add the account to `HkdfGuardUsers`. macOS: run as the user who provisioned it, in a logged-in session. |
| `AccessDeniedException`, status -39 | The key file's location isn't trusted | Move it to a folder prepared as your OS guide shows |
| `InvalidKeyFileException`, status -37 | The "key file" holds an *unwrapped* key | Treat that key as exposed: replace it, and create the file with `wrap` |

## Next steps

- The [hkdfguard-java README](https://github.com/runsecure/hkdfguard-java) covers:
  - how the API differs from .NET, by design;
  - the Linux loader's checks;
  - every status code;
  - running the native integration tests.
- [Separation of duties](../separationofduties.md) explains who should run each step in
  production.
