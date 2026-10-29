---
title: Wrapping keys with Azure Key Vault
sidebar_label: Azure Key Vault
sidebar_position: 2
description: Set up an RSA wrapping key and an EC signing key in Azure Key Vault as HkdfGuard's key encryption key, and use them with AzureKeyVaultKeyWrapper.
---

# Wrapping keys with Azure Key Vault

`AzureKeyVaultKeyWrapper` (package `HkdfGuard.KeyWrapping.AzureKeyVault`) uses two Azure Key Vault
keys as HkdfGuard's KEK: an RSA key wraps each DEK, and a separate EC P-256 key signs it. What all
cloud wrappers share is in the [overview](index.md).

## Why two keys

A Key Vault (Standard or Premium) has no symmetric keys: only RSA keys can wrap, and EC keys can only
sign. RSA-OAEP wrapping needs nothing but the public key, which isn't secret. On its own, anyone
could produce a wrapped DEK holding a key *they* chose, and your application would encrypt new data
under it.

So the wrapper:

- **wraps** each DEK under an RSA key (2048 or 3072 bits) with RSA-OAEP-256, inside Key Vault;
- **signs** each wrapped DEK with a separate EC P-256 key, with ES256, inside Key Vault;
- **verifies the signature before every unwrap**, and unwraps nothing that fails.

A key file the application accepts therefore proves it was made by a principal allowed to sign. Give
that permission to the pipeline, never to the application.

### What a key file holds

| Field | Bytes |
|---|---|
| Magic `HGKV` | 4 |
| Format version (1) | 1 |
| Wrapping key version | 16 |
| Ciphertext length, n | 2 |
| The DEK, wrapped under that version of the RSA key | n (256 or 384) |
| Signing key version | 16 |
| ES256 signature (r ‖ s) | 64 |

Only key *versions* are stored. The vault and key names are the wrapper's own, so a key file can
never point it at another key. The signature covers a fixed HkdfGuard domain string, the wrapper's
context, and every byte before the signing key version.

## 1. Create the keys

Use a vault with **purge protection** on. Deleting a key makes every DEK wrapped under it, and all
data encrypted under those DEKs, permanently unrecoverable; purge protection keeps a deleted key
recoverable for its retention period.

Create both keys, each allowed only the operations it needs:

```bash
az keyvault key create --vault-name myvault --name myapp-wrap --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault key create --vault-name myvault --name myapp-sign --kty EC --curve P-256 --ops sign verify
```

In the portal: **Keys**, **Generate/Import**, **RSA** with 2048 or 3072 bits for the first and
**EC** with **P-256** for the second. Then open each key's version and clear every permitted
operation except those two.

Use 2048 or 3072 bits. A 4096-bit key's wrapped DEK won't fit a key file's 512-byte limit, and
wrapping under one is refused.

Copy each key's **key identifier without the version**, e.g.
`https://myvault.vault.azure.net/keys/myapp-wrap`.

## 2. Grant each identity only what it calls

With Azure RBAC, assign roles on each **key**, not the vault:

| Identity | On the RSA key | On the EC key |
|---|---|---|
| Release pipeline that creates key files | Key Vault Crypto Service Encryption User | Key Vault Crypto User |
| Application | Key Vault Crypto Service Encryption User | Key Vault Crypto Service Encryption User |

The application's role on the EC key lets it read the public key; the SDK verifies with it locally.
It doesn't include `sign`.

```bash
az role assignment create --assignee <app-principal-id> --role "Key Vault Crypto Service Encryption User" \
  --scope "$(az keyvault show -n myvault --query id -o tsv)/keys/myapp-wrap"
```

With vault access policies instead, which apply to the whole vault: the pipeline gets **Get**,
**Wrap Key** and **Sign**; the application **Get**, **Unwrap Key** and **Verify**.

:::danger Never give the application `sign` on the EC key
That means no Key Vault Crypto User, Crypto Officer, or Sign access policy for the application. With
it, anyone controlling the application, and able to replace a key file, could choose its DEK.
:::

## 3. Give the process a credential

Every call is authorized by an Azure `TokenCredential`. Deployed, use a **managed identity**
(`ManagedIdentityCredential`, or `DefaultAzureCredential`, which finds it). On a developer machine,
`DefaultAzureCredential` uses your `az login`. Don't give a deployed process a client secret.

## 4. Create the wrapper

```sh
dotnet add package HkdfGuard.KeyWrapping.AzureKeyVault
dotnet add package Azure.Identity
```

```csharp
using Azure.Identity;
using HkdfGuard.KeyWrapping.AzureKeyVault;

var wrapper = new AzureKeyVaultKeyWrapper(
    wrappingKeyId: new Uri("https://myvault.vault.azure.net/keys/myapp-wrap"),
    signingKeyId: new Uri("https://myvault.vault.azure.net/keys/myapp-sign"),
    credential: new DefaultAzureCredential(),
    context: "com.example.myapp");
```

- **Give key identifiers without a version.** New key files then use each key's current version, and
  every key file records the versions it was made with, so both keys can be rotated in Key Vault with
  no change here. Keep an old version enabled as long as key files made with it are in use.
- **The context** is bound into every key file's signature and must be given again, exactly, to
  reveal it. Use one value per application, so a key file made for one can't be used by another that
  shares the keys. It isn't secret.
- **The two identifiers must name different keys.** The constructor refuses the same key for both.
- Optional arguments: `keyFileTrust` trusts a deployer account (see
  [Where key files can live](index.md#where-key-files-can-live)), and `options` takes
  `CryptographyClientOptions` for the Key Vault clients.

## 5. Create and use key files

The pipeline creates key files with the wrapper, running as the pipeline identity:

```csharp
using HkdfGuard.Abstractions;

var wrapped = new byte[WrappedKeyLimits.MaxBytes];
int length = await wrapper.GenerateAndWrapAsync(wrapped);
await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
```

Key Vault has no "generate data key", so `GenerateAndWrapAsync` generates the DEK in the pipeline's
process and zeroes it once wrapped. To wrap an `AesGcmPipelineDataProtector`'s key, use `WrapAsync`
as in [Wrapping a pipeline key](awskms.md#wrapping-a-pipeline-key).

Then use the wrapper like any other: `KeyRingBuilder.WithKeyWrapper(wrapper)` with
`WithKeyFile(...)` or `WithEphemeralKey(...)`.

Each refresh is a signature verify, which the SDK does locally once it has the public key, and one
unwrap call to Key Vault; see [Choosing a refresh interval](index.md#choosing-a-refresh-interval).
RSA 3072 and EC keys are billed at a higher rate than RSA 2048; see
[Key Vault pricing](https://azure.microsoft.com/pricing/details/key-vault/).

## If something goes wrong

Every failure is a `CryptographicException`. For a Key Vault refusal, the message names its error
code and HTTP status, and the Azure exception is its `InnerException`. A failed unwrap zeroes your
buffer. Reading a key file fails as described for [AWS KMS](awskms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `Forbidden (HTTP 403)` | The identity lacks the operation on that key | Step 2 |
| `KeyNotFound (HTTP 404)` | The identifier is wrong, or the key version a key file names was purged | Check the identifier; restore the version |
| `signature doesn't verify` | The key file was altered, made under another context, or not signed by a principal allowed to sign | Restore it; use the same context |
| `not a wrapped DEK written by AzureKeyVaultKeyWrapper` | The file isn't one of this wrapper's key files | Check the path and wrapper |
| `Use a 2048- or 3072-bit RSA key` | The wrapping key is 4096 bits | Create a smaller RSA key |
| `The signing key must be an EC P-256 key` | The signing key is another curve, or RSA | Create an EC P-256 key |
| `reported key ... instead` | Key Vault answered for a different key | Check both identifiers |
| `CredentialUnavailableException`, `AuthenticationFailedException` (inner) | No credential could get a token | Step 3 |
