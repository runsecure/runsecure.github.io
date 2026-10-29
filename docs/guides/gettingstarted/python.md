---
title: Getting started with Python
sidebar_label: Python
sidebar_position: 8
description: Use HkdfGuard from Python to encrypt data and configuration secrets under a TPM- or Secure Enclave-protected key.
---

# Getting started with Python

This guide takes a Python application from nothing to encrypting and decrypting data under a key
the platform protects. It first checks the setup with an in-memory key. Then it moves to a durable
key file, encrypts configuration secrets in a deployment pipeline, and reads them back at
runtime.

`hkdfguard-python` reads and writes the same values as every other port. Its API is synchronous,
and every closable type is a context manager.

## Before you start

You need:

- **Python 3.12 or later.**
- **The HkdfGuard native library, installed on the machine, with a service provisioned.** Follow
  the guide for your OS first: [Windows](windows.md), [macOS](macos.md) or [Linux](linux.md).
  This guide uses the service name `com.example.myapp`.
- **An account that may use the key.** Your application must run as an account the service's
  key allows:
  - Windows: a member of `HkdfGuardUsers`.
  - Linux: in `tss` and `hkdfguard`.
  - macOS (user-scoped): the user who provisioned it.

The Python library calls the native library through `ctypes`. It loads the library only from its
install location, after checking the location, its ownership, its code signature (Windows and
macOS), and the dynamic linker's environment. It never searches `PATH` or your application
folder.

## 1. Install the packages

Each distribution installs one subpackage of the `hkdfguard` namespace:

| Distribution | Import | What it gives you |
|---|---|---|
| `hkdfguard-dataencryptionkey` | `hkdfguard.dataencryptionkey` | `KeyRing`, `KeyRingBuilder`, data protectors and the `enc::v1::...` format |
| `hkdfguard-cryptoprovider-aesgcm256` | `hkdfguard.cryptoprovider.aesgcm256` | The AES-256-GCM cipher, and `AesGcmPipelineDataProtector` for pipelines |
| `hkdfguard-keywrapping-v1` | `hkdfguard.keywrapping.v1` | `NativeHkdfKeyWrapperV1`, which calls the native library |
| `hkdfguard-options` | `hkdfguard.options` | `HkdfGuardOptions`, to configure the ring from JSON, TOML or YAML |
| `hkdfguard-cache` | `hkdfguard.cache` | `ProtectedCache`, an in-memory cache that holds only ciphertext |
| `hkdfguard-abstractions` | `hkdfguard.abstractions` | The shared interfaces, errors and `ProtectedConfigurationPurpose` |

Releases are published on the
[GitHub Releases page](https://github.com/runsecure/hkdfguard-python/releases): every
distribution's wheel and source archive, with Sigstore build provenance. They aren't on PyPI yet.
Download the wheels, check where they came from, and install them by path:

```sh
gh release download v0.9.0 --repo runsecure/hkdfguard-python --pattern '*.whl'
for wheel in hkdfguard_*.whl; do
    gh attestation verify "$wheel" --repo runsecure/hkdfguard-python
done

python -m venv .venv && . .venv/bin/activate    # .venv\Scripts\activate on Windows
pip install ./hkdfguard_*.whl
```

Installing the wheels together lets pip resolve the packages' dependencies on each other from
the local files. Their other dependencies, such as `cryptography` and `opentelemetry-api`, come
from PyPI.

## 2. Check the setup with an in-memory key

Write `main.py`:

```python
from hkdfguard.abstractions import KeyTrackingValue
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.dataencryptionkey import DefaultFormatProvider, KeyRingBuilder
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1

with (KeyRingBuilder()
        .with_service_name("com.example.myapp")
        .with_key_wrapper(NativeHkdfKeyWrapperV1("com.example.myapp"))
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(60)
        .with_ephemeral_key(1)
        .build()) as ring:
    formats = DefaultFormatProvider()
    aad = b"customer-notes"   # what the value is for

    # Encrypt under the current key. encrypt zeroes the plaintext it is given.
    version, key = ring.get_current()
    ciphertext = key.encrypt(bytearray(b"The launch code is 0000"), aad=aad)
    stored = formats.format(KeyTrackingValue(key_version=version, value=ciphertext))
    print(stored)

    # Decrypt with the key for the value's own version.
    parsed = formats.parse(stored)
    dek = ring.get(parsed.key_version)
    result = bytearray(len(parsed.value))
    try:
        length = dek.decrypt(parsed.value, result, aad=aad)
        print(result[:length].decode())   # a str for the demo only
    finally:
        result[:] = bytes(len(result))   # zero it
```

Run it with `python main.py`:

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `build()` asked the native library to generate a DEK and wrap it under your service's key, then
  unwrapped it into memory that is zeroed when the ring closes. The plaintext DEK never touched
  disk.
- `ring.get_current()` returns the **current version** and its **data encryption key**. `encrypt`
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
- `with_key_refresh_interval(60)` re-checks the key every 60 seconds. If it stops being available,
  encryption and decryption stop after three failed checks, until access returns.
- Plaintext travels in a `bytearray`, so it can be zeroed. A `bytes` or `str` can never be cleared
  from memory.

:::tip The shortcut: data protectors
`ring.create_protector("customer-notes")` does these same steps for text values: it takes the
current key, uses the UTF-8 of its name as the AAD, and formats the result. Values are
interchangeable: a protector named `customer-notes` decrypts the value above, and the reverse.
:::

On macOS, the first run shows a keychain prompt for `python3`: choose **Always Allow**. That
approval covers every script that interpreter runs as that user. For production, ship the
service as its own signed executable (PyInstaller or Nuitka). See
[the first unwrap asks for permission](macos.md#the-first-unwrap-asks-for-permission).

An **ephemeral key** lives only as long as the process, which suits short-lived data. Data you
store needs a key file.

## 3. Use a key file

In a deployment, a deployer wraps each release's DEK into a **key file** with `hkdfguard wrap`, as
the OS guides show. Your application registers it by version:

```python
with (KeyRingBuilder()
        .with_service_name("com.example.myapp")
        .with_key_wrapper(NativeHkdfKeyWrapperV1("com.example.myapp"))
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(60)
        .with_key_file(1, "/etc/myapp/keys/myapp.v1.key")
        .build()) as ring:
    ...
```

Use the path your OS guide prepared:

| OS | Example key file |
|---|---|
| Windows | `C:\HkdfGuardKeys\myapp\myapp.v1.key` (never under `C:\ProgramData`) |
| Linux | `/etc/myapp/keys/myapp.v1.key` |
| macOS | `~/Library/Application Support/MyApp/keys/myapp.v1.key`, or a root-owned folder in production |

The key file is read through the native library. A refusal raises one of these:

- `FileNotFoundError` (-32);
- `PermissionError` (-33, or -39 for an untrusted location);
- `InvalidKeyFileError` (-35 to -38).

**To rotate,** wrap a new DEK as `myapp.v2.key` and add `.with_key_file(2, ...)`. New values use the
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

```python
import subprocess

from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider

with AesGcmPipelineDataProtector(DefaultFormatProvider(), 1) as pipeline:
    # Encrypt each secret for the configuration key it will be stored under.
    value = pipeline.encrypt("Server=db;Password=s3cret", "ConnectionStrings:Admin")
    # ...write "enc::v1::..." into your configuration as ConnectionStrings:Admin...

    # On the target machine, wrap the same key into the release's key file.
    # Add "--group", "<the service's group>" so the application can read it.
    # bufsize=0 writes straight to the pipe, so no buffer of ours keeps a copy of the key.
    tool = subprocess.Popen(
        [tool_path, "wrap", "--service-name", "com.example.myapp",
         "--key-file-path", key_file_path, "--dek-stdin"],
        stdin=subprocess.PIPE, bufsize=0)
    try:
        tool.stdin.write(pipeline.get_key_as_base64())
    finally:
        tool.stdin.close()
    if tool.wait() != 0:
        raise RuntimeError(f"hkdfguard wrap failed with exit code {tool.returncode}")
# Leaving the block zeroes the key and its base64 form.
```

`tool_path` is `C:\Program Files\HkdfGuard\v1\hkdfguard.exe` on Windows, `/usr/bin/hkdfguard` on
Linux, and `/usr/local/bin/hkdfguard` on macOS. Run this step as a deployer, as your OS guide
describes.

:::warning
Pass the DEK only on standard input, as above. Never pass it as a command-line argument or an
environment variable, and never turn `get_key_as_base64()` into `bytes` or a `str`: those can't be
cleared from memory.
:::

## 5. Read the secrets back at runtime

Each configuration value is an `enc::v1::...` string, encrypted for the configuration key it is
stored under. Parse it, take the key for its version, and decrypt it with that configuration
key's AAD:

```python
from hkdfguard.abstractions import ProtectedConfigurationPurpose
from hkdfguard.dataencryptionkey import DefaultFormatProvider

encrypted = config["ConnectionStrings"]["Admin"]   # "enc::v1::..."
value = DefaultFormatProvider().parse(encrypted)
dek = ring.get(value.key_version)

result = bytearray(len(value.value))
try:
    length = dek.decrypt(value.value, result, aad=ProtectedConfigurationPurpose.aad_for("ConnectionStrings:Admin"))
    # use result[:length], the UTF-8 bytes of the secret
finally:
    result[:] = bytes(len(result))
```

`ProtectedConfigurationPurpose.aad_for` gives the AAD the pipeline bound the value to. Use the
configuration key's full path, joined with `:` as .NET writes it (`ConnectionStrings:Admin`), so
the same encrypted value decrypts in every port. A value copied to a different configuration key
fails authentication. The key ring must have the release's key file registered at the version the
pipeline used, here `1`.

## 6. Configure the ring from a settings file

`HkdfGuardOptions.from_mapping` reads a parsed section of JSON, TOML or YAML. It matches keys
ignoring case and underscores, so a .NET `appsettings.json` `HkdfGuard` section reads unchanged.
Unlike .NET's binder, an unknown key is an error, so a misspelt setting can't silently fall back to
a default:

```toml
[hkdfguard]
service_name = "com.example.myapp"
key_refresh_interval = 60
key_files = [{ version = 1, path = "/etc/myapp/keys/myapp.v1.key" }]
```

```python
import tomllib

from hkdfguard.options import HkdfGuardOptions

with open("/etc/myapp/config.toml", "rb") as file:
    options = HkdfGuardOptions.from_mapping(tomllib.load(file)["hkdfguard"]).require_valid()

with (options.apply_to(KeyRingBuilder())
        .with_key_wrapper(NativeHkdfKeyWrapperV1(options.service_name))
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .build()) as ring:
    ...
```

`require_valid()` reports every problem at once.

## 7. Harden the process

DEKs pass through your process's memory. Opt in to process hardening once, first thing at startup,
so crash dumps and other processes of the same user can't read it:

```python
import sys

from hkdfguard.keywrapping.v1 import NativeProcessHardening, ProcessHardeningOptions

if sys.platform == "win32":
    NativeProcessHardening.apply(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE)
else:
    NativeProcessHardening.apply()   # raises RuntimeError if it fails: don't start
```

On Windows, the strict form also closes threads started later: a thread pool, asyncio's default
executor, or a library's background thread. On macOS it fails for an unsigned `python`, so use the
plain form there. Debuggers and `py-spy` stop working for the process.

[Process hardening](../processhardening.md) explains what each platform does, and when to
pass the flag.

## Troubleshooting

Every native error message names the status and what it means.

| You see | Cause | Fix |
|---|---|---|
| `NativeLibraryNotFoundError` | The native library isn't installed | Follow your OS guide's install step |
| `PermissionError` when loading | The installed library, a folder above it, or the dynamic linker's environment failed verification | Reinstall the native package; clear `LD_LIBRARY_PATH` and `DYLD_LIBRARY_PATH` |
| `CryptographicError`, status -17 | No key is provisioned for this service name | Provision it, with the same service name |
| `CryptographicError`, status -18 | The key exists, but this account may not use it | Windows: add the account to `HkdfGuardUsers`. macOS: run as the user who provisioned it, in a logged-in session. |
| `PermissionError`, status -39 | The key file's location isn't trusted | Move it to a folder prepared as your OS guide shows |
| `InvalidKeyFileError`, status -37 | The "key file" holds an *unwrapped* key | Treat that key as exposed: replace it, and create the file with `wrap` |
| `AuthenticationTagMismatchError` | A value was altered, or decrypted under the wrong purpose or configuration key | Use the same purpose or key it was encrypted for |

## Next steps

- The [hkdfguard-python README](https://github.com/runsecure/hkdfguard-python) covers:
  - how the API differs from .NET, by design;
  - the native loader's checks;
  - logging and OpenTelemetry;
  - running the native integration tests.
- [Separation of duties](../separationofduties.md) explains who should run each step in
  production.
