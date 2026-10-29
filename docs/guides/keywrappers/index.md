---
title: Cloud key wrappers
sidebar_label: Overview
sidebar_position: 0
description: Use AWS KMS, Azure Key Vault or Google Cloud KMS as HkdfGuard's key encryption key in place of a TPM or Secure Enclave, and choose between them.
---

# Cloud key wrappers

A key wrapper holds the **key encryption key (KEK)** that wraps and unwraps your data encryption
keys (DEKs). The native wrapper keeps the KEK in the machine's TPM, Secure Enclave or HSM. A cloud
key wrapper keeps it in a cloud key management service instead:

| Wrapper | .NET package | Page |
|---|---|---|
| `AwsKmsKeyWrapper` | `HkdfGuard.KeyWrapping.AwsKms` | [AWS KMS](awskms.md) |
| `AzureKeyVaultKeyWrapper` | `HkdfGuard.KeyWrapping.AzureKeyVault` | [Azure Key Vault](azurekeyvault.md) |
| `GoogleKmsKeyWrapper` | `HkdfGuard.KeyWrapping.GoogleKms` | [Google Cloud KMS](googlekms.md) |

Each is an `IKeyWrapper`, so it goes wherever `NativeHkdfKeyWrapperV1` would:
`KeyRingBuilder.WithKeyWrapper(wrapper)`, with ephemeral keys or key files. Nothing else in your
application changes, and nothing native needs installing.

## When to use one

Use a cloud key wrapper when your application runs in a cloud, or anywhere it can reach one, and you
want key access controlled by the cloud's identity system and recorded in its audit log, rather than
tied to one machine's hardware. Containers and autoscaled hosts with no TPM are the usual case.

| | Native | Cloud |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or HSM | A key in AWS KMS, Azure Key Vault or Google Cloud KMS |
| Identified by | A service name | A key ARN, key identifier or resource name |
| Who may unwrap | Local accounts and groups the native library allows | Identities the cloud's IAM allows |
| Each call | Local | A request over the network, in the cloud's audit log |
| Key files are made | On the host that uses them, with `hkdfguard wrap` | Anywhere the pipeline has credentials, with the wrapper itself |
| Install | The native package | Nothing beyond the library package |

Wrapped DEKs aren't interchangeable. A key file belongs to the wrapper that made it.

## Comparing the three

| | AWS KMS | Azure Key Vault | Google Cloud KMS |
|---|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign | One symmetric key |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key | Principals allowed `useToEncrypt` |
| Context binding | Encryption context (AAD) | A context string bound into the signature | A context string bound as AAD, after a fixed HkdfGuard label |
| New DEKs | Generated inside KMS; the plaintext never leaves it | Generated in the process, wrapped, then zeroed | Generated in the process, wrapped, then zeroed |
| Key pinning | The key is pinned on every `Decrypt` | Key names are the wrapper's; a key file holds only versions | The key is pinned on every `Decrypt` |
| Integrity in transit | TLS | TLS, plus the signature | TLS, plus CRC32C on every request and response |
| Wrapped DEK size | About 184 bytes | 359 bytes (RSA 2048) or 487 bytes (RSA 3072) | Well under the 512-byte limit |

## The rule that matters most: keep "create" away from the application

Symmetric encryption and RSA wrapping need no secret beyond permission to use the key. Anyone who
can wrap under your KEK, and can replace a key file, can choose your application's DEK, and your
application would then encrypt new data under a key they know. So every wrapper splits the roles:

| | Release pipeline (creates key files) | Application (reads key files) |
|---|---|---|
| AWS KMS | `kms:Encrypt`, `kms:GenerateDataKeyWithoutPlaintext` | `kms:Decrypt` |
| Azure Key Vault | Wrap on the RSA key, **sign** on the EC key | Unwrap on the RSA key, verify on the EC key |
| Google Cloud KMS | `roles/cloudkms.cryptoKeyEncrypter` | `roles/cloudkms.cryptoKeyDecrypter` |

Never give the application the pipeline's permissions. This is the cloud form of
[separation of duties](../separationofduties.md).

## Where key files can live

Every cloud wrapper reads key files only from where no untrusted account could have written or
replaced them, by the same rules the native library applies, checked in managed code
(`HkdfGuard.SecureFile`):

- **Windows:** the file is on a local fixed drive, not a UNC path or network drive, and its path runs
  through no symbolic link, junction or substituted drive. The file and every folder above it are
  owned by SYSTEM, Administrators or TrustedInstaller, and grant no one else the right to write,
  delete, rename, change permissions or take ownership. Nothing under `C:\ProgramData`, a user
  profile or `%TEMP%` qualifies, nor a folder made directly under `C:\` with its default permissions.
- **Linux and macOS:** the file and every directory above it, up to `/`, are owned by root and
  writable by neither their group nor others. A symbolic link is followed only if root owns it.
  Nothing under `/tmp`, `/var/tmp` or a home directory qualifies.
- **Everywhere:** a file that is empty, over 512 bytes, exactly 32 bytes, or a 32-byte key written as
  hex or base64 is refused. Those last ones are probably a plaintext key: treat it as exposed.

Prepare the folder once, as an administrator. On Windows:

```powershell
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T
```

On Linux:

```bash
sudo install -d -o root -g myapp -m 0750 /etc/hkdfguard/keys/myapp
sudo install -o root -g myapp -m 0640 v1.key /etc/hkdfguard/keys/myapp/
```

If the pipeline writes key files as an account of its own, trust it explicitly with a
`KeyFileTrust`, passed as each wrapper's `keyFileTrust` argument:

```csharp
using HkdfGuard.SecureFile;

var trust = new KeyFileTrust
{
    // Windows: the deployer's SID (Get-LocalUser deployer | Select-Object SID).
    WindowsPrincipals = ["S-1-5-21-1111111111-2222222222-3333333333-1005"],
    // Linux and macOS: the deployer's uid, and a group allowed to write (id deployer).
    UnixUserIds = [1001],
    UnixGroupIds = [2001],
};
```

:::warning
Never trust the account the application itself runs as, except on a developer machine. An
application that can rewrite its own key files can be made to switch to an older, still-valid one.
Everyone, Authenticated Users, Users, Interactive and Anonymous are refused if listed.
:::

## Creating key files

The release pipeline creates key files with the wrapper itself, running as the pipeline identity:

```csharp
using HkdfGuard.Abstractions;

var wrapped = new byte[WrappedKeyLimits.MaxBytes];
int length = await wrapper.GenerateAndWrapAsync(wrapped);
await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
```

If the pipeline also encrypts configuration secrets with `AesGcmPipelineDataProtector`, wrap that
protector's key with `WrapAsync` instead; see [AWS KMS](awskms.md#wrapping-a-pipeline-key).

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `KeyRefreshInterval`, which is one unwrap call to the
cloud. After three failed refreshes in a row (by default) the ring suspends encryption and
decryption until the service answers again. So the interval trades how quickly a revoked grant stops
the process against the number of requests:

| Interval | Unwrap calls per key, per process, per 30 days | A revocation stops the process within |
|---|---|---|
| 60 seconds | 43,200 | about 3 minutes |
| 300 seconds (the maximum) | 8,640 | about 15 minutes |

Multiply by the number of registered keys and running processes, and check your provider's pricing.
The failure count also sets how long an outage is ridden out; change it with
`WithMaxRefreshFailures`.

## Other languages

Every language library has the same three wrappers, and each repository's `docs/how-to` folder has
its own setup pages:

| Language | AWS KMS | Azure Key Vault | Google Cloud KMS |
|---|---|---|---|
| .NET | `HkdfGuard.KeyWrapping.AwsKms` | `HkdfGuard.KeyWrapping.AzureKeyVault` | `HkdfGuard.KeyWrapping.GoogleKms` |
| Java (`io.github.runsecure`) | `hkdfguard-keywrapping-awskms` | `hkdfguard-keywrapping-azurekeyvault` | `hkdfguard-keywrapping-googlekms` |
| Go | `github.com/runsecure/hkdfguard-go/keywrapping/awskms` | `.../keywrapping/azurekeyvault` | `.../keywrapping/googlekms` |
| Node.js | `@runsecure/hkdfguard-keywrapping-awskms` | `@runsecure/hkdfguard-keywrapping-azurekeyvault` | `@runsecure/hkdfguard-keywrapping-googlekms` |
| Python | `hkdfguard-keywrapping-awskms` | `hkdfguard-keywrapping-azurekeyvault` | `hkdfguard-keywrapping-googlekms` |

The cloud setup on these pages (keys, roles, credentials) is the same whichever language you use.
