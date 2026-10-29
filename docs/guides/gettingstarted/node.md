---
title: Getting started with Node.js
sidebar_label: Node.js
sidebar_position: 7
description: Use HkdfGuard from Node.js and TypeScript to encrypt data and configuration secrets under a TPM- or Secure Enclave-protected key.
---

# Getting started with Node.js

This guide takes a Node.js application from nothing to encrypting and decrypting data under a key
the platform protects. It first checks the setup with an in-memory key. Then it moves to a durable
key file, encrypts configuration secrets in a deployment pipeline, and reads them back at
runtime.

`hkdfguard-node` is written in TypeScript and ships its type declarations. It reads and writes the
same values as every other port.

## Before you start

You need:

- **Node.js 22 or later.** Node.js 22.18 and later run the TypeScript in this guide directly; on
  an earlier 22.x, add `--experimental-strip-types` to each `node` command.
- **Python 3 and a C compiler.** The key wrapper package compiles a small native add-on when it is
  installed:
  - Windows: Visual Studio Build Tools with the "Desktop development with C++" workload.
  - macOS: the Xcode Command Line Tools (`xcode-select --install`).
  - Linux: `gcc` and `make`.
- **The HkdfGuard native library, installed on the machine, with a service provisioned.** Follow
  the guide for your OS first: [Windows](windows.md), [macOS](macos.md) or [Linux](linux.md).
  This guide uses the service name `com.example.myapp`.
- **An account that may use the key.** Your application must run as an account the service's
  key allows:
  - Windows: a member of `HkdfGuardUsers`.
  - Linux: in `tss` and `hkdfguard`.
  - macOS (user-scoped): the user who provisioned it.

The add-on does nothing but load the native library and call it. Every check before loading is in
TypeScript:

- the library is loaded only from its install location, never from `PATH`, `node_modules` or your
  application folder;
- the folder's ownership and the library's code signature (Windows and macOS) are verified;
- the dynamic linker's environment is checked.

Key operations run on libuv's thread pool, so a slow TPM never blocks the event loop.

## 1. Add the packages

| Package | What it gives you |
|---|---|
| `@runsecure/hkdfguard-dek` | `buildKeyRing`, key rings, data protectors, the `enc::v1::...` format, and options from `appsettings.json` |
| `@runsecure/hkdfguard-cryptoprovider-aesgcm256` | The AES-256-GCM cipher, and `AesGcmPipelineDataProtector` for pipelines |
| `@runsecure/hkdfguard-keywrapping-native-v1` | `NativeKeyWrapperV1`, which calls the native library through its add-on |
| `@runsecure/hkdfguard-encryptedconfig` | `EncryptedConfigurationReader`, which reads encrypted secrets from any configuration source |
| `@runsecure/hkdfguard-cache` | `ProtectedCache`, an in-memory cache that holds only ciphertext |
| `@runsecure/hkdfguard-abstractions` | The shared interfaces, errors and the `wipe` helper |

```sh
mkdir hkdfguarddemo && cd hkdfguarddemo
npm init -y && npm pkg set type=module
npm install @runsecure/hkdfguard-abstractions @runsecure/hkdfguard-dek \
    @runsecure/hkdfguard-cryptoprovider-aesgcm256 @runsecure/hkdfguard-keywrapping-native-v1
```

If `npm install` fails in node-gyp, Python 3 or the C compiler is missing.

:::note Where the packages come from
Releases are published on the
[GitHub Releases page](https://github.com/runsecure/hkdfguard-node/releases) as `.tgz` files,
with build-provenance attestations. They are published to npm, with provenance, once the project
turns npm publishing on. Until then, install the downloaded files by path:
`npm install ./runsecure-hkdfguard-dek-0.9.0.tgz ...`.
:::

## 2. Check the setup with an in-memory key

Write `main.ts`:

```ts
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { buildKeyRing, DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { NativeKeyWrapperV1 } from '@runsecure/hkdfguard-keywrapping-native-v1';

const ring = await buildKeyRing({
  keyWrapper: NativeKeyWrapperV1.create('com.example.myapp'),
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 60,
  ephemeralKeys: [1],
});
try {
  const formats = new DefaultFormatProvider();
  const aad = new TextEncoder().encode('customer-notes'); // what the value is for

  // Encrypt under the current key. encrypt zeroes the plaintext it is given.
  const { version, key } = ring.getCurrent();
  const ciphertext = key.encrypt(new TextEncoder().encode('The launch code is 0000'), aad);
  const stored = formats.format({ keyVersion: version, value: ciphertext });
  console.log(stored);

  // Decrypt with the key for the value's own version.
  const parsed = formats.parse(stored);
  const dek = ring.get(parsed.keyVersion);
  const result = new Uint8Array(parsed.value.length);
  try {
    const n = dek.decrypt(parsed.value, result, aad);
    console.log(new TextDecoder().decode(result.subarray(0, n))); // a string for the demo only
  } finally {
    wipe(result);
  }
} finally {
  await ring.close();
}
```

Run it with `node main.ts`:

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `buildKeyRing` asked the native library to generate a DEK and wrap it under your service's key,
  then unwrapped it into memory that is zeroed when the ring closes. The plaintext DEK never touched
  disk.
- `ring.getCurrent()` returns the **current version** and its **data encryption key**. `encrypt`
  seals the bytes with AES-256-GCM under that key, bound to the AAD, and zeroes the plaintext it was
  given.
- `DefaultFormatProvider.format` turns the version and the ciphertext into the stored form,
  `enc::v1::...`: `v1` is the key version, and the rest is the ciphertext in base64. However you
  store a value, keep its version with it.
- To decrypt, `ring.get(version)` returns the key **for the value's own version**, not the current
  one, so a value encrypted before a rotation still decrypts. A result buffer as long as the
  ciphertext always fits the plaintext.
- The **AAD** says what the value is for. It is bound into the ciphertext, so decrypting with
  different AAD fails authentication: a value encrypted for one purpose never decrypts as another.
- `keyRefreshInterval: 60` re-checks the key every 60 seconds. If it stops being available,
  encryption and decryption stop after three failed checks, until access returns.
- Plaintext travels as a `Uint8Array`, so it can be zeroed: `wipe` clears the result buffer when
  you are done.

:::tip The shortcut: data protectors
`ring.createProtector('customer-notes')` does these same steps for text values: it takes the current
key, uses the UTF-8 of its name as the AAD, and formats the result. Values are interchangeable: a
protector named `customer-notes` decrypts the value above, and the reverse.
:::

On macOS, the first run shows a keychain prompt for `node`: choose **Always Allow**. That
approval covers every script that `node` executable runs as that user, and a new Node.js version
asks again. See
[the first unwrap asks for permission](macos.md#the-first-unwrap-asks-for-permission).

An **ephemeral key** lives only as long as the process, which suits short-lived data. Data you
store needs a key file.

## 3. Use a key file

In a deployment, a deployer wraps each release's DEK into a **key file** with `hkdfguard wrap`, as
the OS guides show. Your application registers it by version:

```ts
const ring = await buildKeyRing({
  keyWrapper: NativeKeyWrapperV1.create('com.example.myapp'),
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 60,
  keyFiles: { 1: '/etc/myapp/keys/myapp.v1.key' },
});
```

Use the path your OS guide prepared:

| OS | Example key file |
|---|---|
| Windows | `C:\HkdfGuardKeys\myapp\myapp.v1.key` (never under `C:\ProgramData`) |
| Linux | `/etc/myapp/keys/myapp.v1.key` |
| macOS | `~/Library/Application Support/MyApp/keys/myapp.v1.key`, or a root-owned folder in production |

**To rotate,** wrap a new DEK as `myapp.v2.key` and register `keyFiles: { 1: v1Path, 2: v2Path }`.
New values use the highest version. Older values still decrypt for as long as their key file
stays registered.

**Mixing key files and ephemeral keys.** A ring can hold both. Ephemeral keys rotate (every 24
hours by default), and each rotation adds a key at the current version + 1. So give the ephemeral
key a version above every key file, or turn ephemeral rotation off. Otherwise the first rotation
would replace the key file as the current key, and values encrypted after it would be lost on a
restart. The builder refuses such a ring.

## 4. Encrypt configuration secrets in your pipeline

Your release pipeline creates the DEK and encrypts the application's secrets under it. Then, on
the target machine, it hands the same DEK to `hkdfguard wrap`. Each secret is bound to the
configuration key it is stored under, so a value moved to another key fails to decrypt:

```ts
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';

const pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 1);
try {
  // Encrypt each secret for the configuration key it will be stored under.
  const value = pipeline.encrypt(new TextEncoder().encode('Server=db;Password=s3cret'), 'ConnectionStrings:Admin');
  // ...write "enc::v1::..." into appsettings.json as ConnectionStrings:Admin...

  // On the target machine, wrap the same key into the release's key file.
  // Add '--group', '<the service's group>' so the application can read it.
  const tool = spawn(toolPath, ['wrap', '--service-name', 'com.example.myapp',
    '--key-file-path', keyFilePath, '--dek-stdin'], { stdio: ['pipe', 'inherit', 'inherit'] });
  const exited = once(tool, 'close');
  // A tool that exits before reading its input breaks the pipe; its exit code says why.
  let writeError: Error | undefined;
  tool.stdin.on('error', (error) => { writeError = error; });

  // The key crosses to the tool as bytes from the protector's own buffer, never through a string.
  tool.stdin.end(pipeline.keyBase64());
  const [code] = await exited;
  if (code !== 0) throw new Error(`hkdfguard wrap exited with code ${code}`);
  if (writeError !== undefined) throw writeError;
} finally {
  pipeline.close(); // zeroes the key and its base64 form
}
```

`toolPath` is `C:\Program Files\HkdfGuard\v1\hkdfguard.exe` on Windows, `/usr/bin/hkdfguard` on
Linux, and `/usr/local/bin/hkdfguard` on macOS. Run this step as a deployer, as your OS guide
describes.

:::warning
Pass the DEK only on standard input, as above. Never pass it as a command-line argument or an
environment variable, and never decode `keyBase64()` into a `string` (with `TextDecoder`,
`Buffer.toString` or a template literal): strings can't be cleared from memory.
:::

## 5. Read the secrets back at runtime

Each configuration value is an `enc::v1::...` string, encrypted for the configuration key it is
stored under. Parse it, take the key for its version, and decrypt it with that configuration
key's AAD:

```ts
import { configurationAad, wipe } from '@runsecure/hkdfguard-abstractions';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';

const encrypted = settings['ConnectionStrings:Admin']; // "enc::v1::..."
const value = new DefaultFormatProvider().parse(encrypted);
const dek = ring.get(value.keyVersion);

const result = new Uint8Array(value.value.length);
try {
  const n = dek.decrypt(value.value, result, configurationAad('ConnectionStrings:Admin'));
  // use result.subarray(0, n), the UTF-8 bytes of the secret
} finally {
  wipe(result);
}
```

`configurationAad` gives the AAD the pipeline bound the value to. A value copied to a different
configuration key fails authentication. The key ring must have the release's key file registered
at the version the pipeline used, here `1`.

:::tip The shortcut: `EncryptedConfigurationReader`
`@runsecure/hkdfguard-encryptedconfig` does these same steps over any configuration source, through
a lookup function. `flattenJson` and `mapLookup` read an `appsettings.json`, and `envLookup('APP_')`
reads `A:B` from `APP_A__B`, as .NET does: `await new EncryptedConfigurationReader(ring,
mapLookup(flattenJson(json))).decrypt('ConnectionStrings:Admin', buffer)`.
:::

## 6. Configure the ring from appsettings.json

The same `HkdfGuard` section the .NET port reads also configures the Node ring:

```json
{
  "HkdfGuard": {
    "ServiceName": "com.example.myapp",
    "KeyRefreshInterval": 60,
    "KeyFiles": [ { "Version": 1, "Path": "/etc/myapp/keys/myapp.v1.key" } ]
  }
}
```

```ts
import { buildKeyRing, keyRingConfigFromOptions, keyRingOptionsFromJson } from '@runsecure/hkdfguard-dek';

const options = keyRingOptionsFromJson(appsettings); // the "HkdfGuard" section
const ring = await buildKeyRing(keyRingConfigFromOptions(options,
  NativeKeyWrapperV1.create(options.ServiceName!), new AesGcmCryptoProviderFactory()));
```

`keyRingConfigFromOptions` checks every rule and throws `InvalidOptionsError` listing every
problem at once. Like .NET's binder, field names match ignoring case, and numbers may be given as
strings, which is how environment-variable overrides arrive.

## 7. Harden the process

DEKs pass through your process's memory. Opt in to process hardening once, at startup, so crash
dumps and other processes of the same user can't read it:

```ts
import { hardenProcess } from '@runsecure/hkdfguard-keywrapping-native-v1';

hardenProcess({ requireProtectedSignature: process.platform === 'win32' }); // throws if it fails
```

On Windows, the strict form also closes threads Node starts later, such as libuv's thread pool.
On macOS it fails for an unsigned `node`, so use the plain form there. Debuggers and the inspector
stop working for the process.

[Process hardening](../processhardening.md) explains what each platform does, and when to
pass the flag.

## Troubleshooting

Every error is an `HkdfGuardError` with a stable `code`. A failed native call is a `StatusError`,
whose `status` is the native code and whose message includes its meaning.

| You see | Cause | Fix |
|---|---|---|
| `NotInstalledError` | The native library isn't installed | Follow your OS guide's install step |
| `UntrustedError` | The installed library, or a folder above it, failed verification, or a linker variable shadows it | Reinstall the native package; clear `LD_LIBRARY_PATH` and `DYLD_LIBRARY_PATH` |
| `UnsupportedPlatformError` | An x64 `node` under Rosetta, an Intel Mac, or the add-on was never compiled | Use an arm64 `node` on Apple silicon; install Python 3 and a C compiler, then run `npm rebuild @runsecure/hkdfguard-keywrapping-native-v1` |
| `StatusError` -17 | No key is provisioned for this service name | Provision it, with the same service name |
| `StatusError` -18 | The key exists, but this account may not use it | Windows: add the account to `HkdfGuardUsers`. macOS: run as the user who provisioned it, in a logged-in session. |
| `StatusError` -16 or -11 | The key file was wrapped under another service's key, or altered | Use the right service name, or redeploy the key file |
| `StatusError` -39 | The key file's location isn't trusted | Move it to a folder prepared as your OS guide shows |
| `KeyAccessSuspendedError` | The key stopped answering for three refreshes in a row | Restore access to the key; operations resume on the next successful refresh |

## Next steps

- The [hkdfguard-node documentation](https://github.com/runsecure/hkdfguard-node/tree/main/docs)
  covers the `hkdfguard` tool reference, `ProtectedCache` with pull-through sources, diagnostics
  with OpenTelemetry, and running the native integration tests.
- [Separation of duties](../separationofduties.md) explains who should run each step in
  production.
