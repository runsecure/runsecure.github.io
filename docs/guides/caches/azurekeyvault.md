---
title: Caching Azure Key Vault secrets
sidebar_label: Azure Key Vault
sidebar_position: 1
description: Read secrets from one Azure Key Vault on demand with AzureKeyVaultSecretCache, holding them in memory only as ciphertext under your key ring.
---

# Caching Azure Key Vault secrets

`AzureKeyVaultSecretCache` (package `HkdfGuard.Cache.AzureKeyVault`) reads secrets from one Azure
Key Vault on demand and caches them encrypted under your key ring. How every cache works is in the
[overview](index.md); this page covers what's particular to Key Vault.

## 1. Grant the application read access

Assign the application's identity the **Key Vault Secrets User** role, on the vault or on
individual secrets. It allows `get` on secret values, nothing else. The cache never lists the
vault, so it doesn't need `list`.

```bash
az role assignment create --assignee <app-principal-id> --role "Key Vault Secrets User" \
  --scope "$(az keyvault show -n myvault --query id -o tsv)"
```

With vault access policies instead, give the application **Get** on secrets only.

Deployed, authenticate with a **managed identity**; on a developer machine,
`DefaultAzureCredential` uses your `az login`. Don't give a deployed process a client secret.

## 2. Create the cache

```sh
dotnet add package HkdfGuard.Cache.AzureKeyVault
dotnet add package Azure.Identity
```

```csharp
using Azure.Identity;
using HkdfGuard.Cache.AzureKeyVault;

var secrets = new AzureKeyVaultSecretCache(
    new Uri("https://myvault.vault.azure.net/"),
    new DefaultAzureCredential(),
    ring);

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("Db-Password", buffer); // 0 if the secret doesn't exist
```

The first lookup of a name calls `GetSecret` for that one secret's current version. The key ring is
yours: the cache never disposes it.

### Client options

To set your own transport, retries or timeouts, pass a `SecretClientOptions` as the fourth argument
rather than a ready-made client. The cache adds its capture policy to the options you pass, since
the SDK can't copy one:

- **Use a fresh `SecretClientOptions` per cache.** The policy acts only on the cache's own fetches,
  so another `SecretClient` built from the same options is unaffected, but each cache built from
  the same instance adds the policy again.
- **Changes after the constructor returns don't reach the cache.**
- **Content logging is refused.** If `Diagnostics.IsLoggingContentEnabled` is on, the constructor
  throws `ArgumentException`: it would log every secret's value.

## Names

Key Vault secret names are 1-127 ASCII letters, digits and hyphens, and Key Vault ignores case.
The cache does too: `Db-Password` and `db-password` are the same entry. Anything else, such as
`ConnectionStrings:Admin` or `Db_Password`, returns 0 without a call.
`AzureKeyVaultSecretCache.IsValidSecretName` tells you in advance.

A secret holding a JSON object can be read by key, as `App-Login#user`. Keys match exactly, even
though secret names don't: `app-login#user` is the same key, `App-Login#User` is another. See
[Secrets holding several keys](index.md#secrets-holding-several-keys).

## Missing secrets and failures

| Key Vault answers | The cache |
|---|---|
| 404, or an empty value | Returns 0, and looks the name up again next time |
| 403 (access denied) | Throws the Azure `RequestFailedException` |
| A disabled secret | Throws |
| No answer (vault unreachable, DNS) | Throws |

A cached value isn't refreshed. After rotating a secret, a new cache instance picks up the new
version.

## Asynchronous lookups

`DecryptAsync` and `GetMaxDecryptedLengthAsync` fetch with `GetSecretAsync`, reading the response
into the same pinned memory without blocking a thread. Prefer them in ASP.NET Core; see
[Reading asynchronously](index.md#reading-asynchronously).
