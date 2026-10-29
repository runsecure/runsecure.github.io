---
title: Caching Google Cloud Secret Manager secrets
sidebar_label: Google Secret Manager
sidebar_position: 3
description: Read secrets from one Google Cloud project's Secret Manager on demand with GoogleSecretManagerSecretCache, holding them in memory only as ciphertext under your key ring.
---

# Caching Google Cloud Secret Manager secrets

`GoogleSecretManagerSecretCache` (package `HkdfGuard.Cache.GoogleSecretManager`) reads secrets from
one Google Cloud project's Secret Manager on demand and caches them encrypted under your key ring.
How every cache works is in the [overview](index.md); this page covers what's particular to Secret
Manager.

## 1. Grant the application read access

The cache calls only `AccessSecretVersion`, for the `latest` version of the one secret asked for. It
never lists secrets or versions. Grant the **Secret Manager Secret Accessor** role
(`roles/secretmanager.secretAccessor`, which holds `secretmanager.versions.access`), preferably on
each secret rather than the project:

```bash
gcloud secrets add-iam-policy-binding Db-Password --project my-project \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com" \
  --role roles/secretmanager.secretAccessor
```

The client signs in with Application Default Credentials. Deployed, use the **attached service
account** (Compute Engine, Cloud Run, GKE Workload Identity), or Workload Identity Federation
outside Google Cloud. Don't give a deployed process a service account key file.

## 2. Create the cache

```sh
dotnet add package HkdfGuard.Cache.GoogleSecretManager
```

```csharp
using Google.Apis.Auth.OAuth2;
using HkdfGuard.Cache.GoogleSecretManager;

using var secrets = GoogleSecretManagerSecretCache.Create(
    "my-project", await GoogleCredential.GetApplicationDefaultAsync(), ring);

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("Db-Password", buffer); // 0 if the secret doesn't exist
```

- **`Create` makes and owns a gRPC channel**, scoped as Secret Manager needs. Dispose the cache to
  close it. The key ring is yours.
- **To use your own channel**, pass its `CallInvoker` to the constructor instead:
  `new GoogleSecretManagerSecretCache(channel.CreateCallInvoker(), "my-project", ring)`. The cache
  adds its own interceptor to zero gRPC's receive buffer, and doesn't dispose your channel.
- **The project** is its ID or number. Anything but ASCII letters, digits, hyphens, dots and colons
  is refused, since it's spliced into every resource name.

## Names

Secret IDs are 1-255 ASCII letters, digits, hyphens and underscores; anything else returns 0
without a call. `GoogleSecretManagerSecretCache.IsValidSecretName` tells you in advance. IDs match
exactly, as Secret Manager matches them: `Db` and `db` are separate secrets and separate entries.

The payload is cached as its bytes. A payload holding a JSON object can also be read by key, as
`App-Login#user`; see [Secrets holding several keys](index.md#secrets-holding-several-keys).

## Integrity checks

Every response is checked before anything is cached:

- **CRC32C.** If Google returns a checksum and the payload doesn't match it, the response is refused
  with `CryptographicException`: it was corrupted in transit.
- **The secret's name.** A response naming a different secret than the one asked for is refused
  with `CryptographicException`.

The payload is zeroed whether it's accepted or refused.

## Missing secrets and failures

| Secret Manager answers | The cache |
|---|---|
| `NotFound`: no such secret, or no versions | Returns 0, and looks the name up again next time |
| The latest version is disabled or destroyed | Throws the gRPC `RpcException` |
| `PermissionDenied`, `Unauthenticated`, or no answer | Throws the gRPC `RpcException` |
| A bad checksum, or the wrong secret's name | Throws `CryptographicException` |

A cached value isn't refreshed. After adding a secret version, a new cache instance picks it up.

## Asynchronous lookups

`DecryptAsync` and `GetMaxDecryptedLengthAsync` call `AccessSecretVersionAsync` without blocking a
thread. Prefer them in ASP.NET Core; see [Reading asynchronously](index.md#reading-asynchronously).
