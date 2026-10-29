---
title: Caching HashiCorp Vault secrets
sidebar_label: HashiCorp Vault
sidebar_position: 4
description: Read secrets from a HashiCorp Vault KV secrets engine on demand with HashiCorpVaultSecretCache, holding them and the Vault token in memory only as ciphertext under your key ring.
---

# Caching HashiCorp Vault secrets

`HashiCorpVaultSecretCache` (package `HkdfGuard.Cache.HashiCorpVault`) reads secrets from one
HashiCorp Vault KV secrets engine, version 2 or 1, on demand and caches them encrypted under your key
ring. How every cache works is in the [overview](index.md); this page covers what's particular to
Vault.

Unlike the cloud caches, it uses no SDK. It calls Vault's HTTP API itself, so it can read the
response straight into pinned memory, and it has no dependency beyond `HkdfGuard.Cache`.

## 1. Write a read-only policy

The cache only reads: a `GET` on the secret's path (for KV version 2, its latest version). It never
lists. Give the application's token a policy with `read` on exactly the paths it needs:

```hcl
# KV version 2 mounted at "secret": reads go to secret/data/<path>
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
```

For KV version 1, the path has no `data/` segment: `path "kv/myapp/*"`.

## 2. Protect the token

The cache never holds the Vault token in plain text. It asks a token provider for the token on
every fetch, and the provider hands it over **protected**: encrypted by a data protector on the key
ring, created for the cache's purpose:

```csharp
var tokenProtector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
```

The cache decrypts the token only as each request is built, into stack or pinned memory, then into
the one string the `X-Vault-Token` header needs (an HTTP header can only be a string), and zeroes
that string's memory as soon as the request has been sent. The token's plaintext lives for one
request. A token that isn't protected that way (plain text, another purpose, another ring, a key
version the ring no longer holds) fails the fetch with `InvalidOperationException`, without calling
Vault or quoting what it was given.

### A token you already hold

`StaticVaultToken` holds a token issued elsewhere, such as `VAULT_TOKEN`, in protected form:

```csharp
var token = StaticVaultToken.Protect(tokenProtector, Environment.GetEnvironmentVariable("VAULT_TOKEN"));
```

Nothing renews or replaces it. Once it expires or is revoked, every fetch fails with 403.

### Logging in and renewing

Authentication isn't the cache's job. Implement `IVaultTokenProvider` to log in with AppRole,
Kubernetes, a certificate, or anything else, and to renew or replace the token before it expires.
Return the token protected:

```csharp
public sealed class MyVaultLogin(IDataProtector tokenProtector) : IVaultTokenProvider
{
    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        // Log in or renew as needed, then hand the token over protected - never in plain text.
        char[] token = await LogInOrRenewAsync(cancellationToken);
        try
        {
            return tokenProtector.Encrypt(token);
        }
        finally
        {
            ArrayUtility.ZeroMemory(token.AsSpan());
        }
    }
}
```

`GetTokenAsync` is called on every fetch, and its cancellation token is cancelled once the cache's
`Timeout` has passed. A provider's failure isn't retried; it propagates as it is.

## 3. Create the cache

```sh
dotnet add package HkdfGuard.Cache.HashiCorpVault
```

```csharp
using HkdfGuard.Cache.HashiCorpVault;

var tokenProtector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
using var secrets = new HashiCorpVaultSecretCache(
    new Uri("https://vault.example.com:8200"),
    StaticVaultToken.Protect(tokenProtector, Environment.GetEnvironmentVariable("VAULT_TOKEN")),
    tokenProtector,
    ring,
    new HashiCorpVaultSecretCacheOptions { MountPath = "secret" });

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("myapp/db#password", buffer); // 0 if there's no such secret or key
```

- **The address** is the same value as `VAULT_ADDR`. It must be `https`, except on a loopback
  address (a local Vault Agent or dev server). A path, if any, is kept as a prefix, for Vault behind
  a reverse proxy. Credentials, a query or a fragment in it are refused.
- **Dispose the cache** to release its connections. The key ring is yours.

### Options

| Option | Default | What it does |
|---|---|---|
| `MountPath` | `secret` | Where the KV engine is mounted, e.g. `kv/team-a` |
| `KvVersion` | `V2` | `V2` reads `{mount}/data/{path}` (the latest version); `V1` reads `{mount}/{path}` |
| `DefaultKey` | `value` | The key read for a name without `#` |
| `Namespace` | none | Sent as `X-Vault-Namespace`, for Vault Enterprise, e.g. `team-a/prod` |
| `Timeout` | 30 seconds | How long one attempt may take: getting the token, or one request and its whole response |
| `RetryCount` | 3 | Retries for a transient failure, 3 to 10 |
| `RetryDelay` | 200 ms | The wait before the first retry, doubling each time, up to 10 seconds |
| `HttpMessageHandler` | the cache's own | Sends every request, to trust a private CA or use a proxy. Not disposed by the cache |
| `AllowRedirects` | `false` | Accepts a handler that follows redirects |

### Redirects carry the token

When .NET follows a redirect it drops only the `Authorization` header, so `X-Vault-Token` would go
wherever the redirect points. The cache's own handler follows no redirects. A `SocketsHttpHandler`
or `HttpClientHandler` you pass follows them by default, so the cache refuses one with
`AllowAutoRedirect` still on:

```csharp
new HashiCorpVaultSecretCacheOptions
{
    HttpMessageHandler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        SslOptions = { RemoteCertificateValidationCallback = ValidateAgainstPrivateCa },
    },
}
```

Set `AllowRedirects` only if every address a redirect could lead to may see the token. Don't pass a
handler that logs response content.

## Names

A Vault secret holds several keys, so a name is the secret's path with the key after `#`:

| Name | Reads |
|---|---|
| `myapp/db#password` | The `password` key of the secret at `myapp/db` |
| `myapp/db` | Its `DefaultKey` (`value` unless set) |

One read caches every key the secret holds, so the first lookup of any of them reads the secret once
and the rest are already cached. See [Secrets holding several keys](index.md#secrets-holding-several-keys).

Paths and keys match exactly, as Vault's do. A name whose path segments aren't ASCII letters,
digits, `-`, `_` and `.`, that holds a `.` or `..` segment, or that's over 512 characters returns 0
without a call. `HashiCorpVaultSecretCache.IsValidSecretName` tells you in advance.

## Missing secrets and failures

| Vault answers | The cache |
|---|---|
| 404 with no errors: no such secret | Returns 0, and looks the name up again next time |
| The latest version is deleted or destroyed | Returns 0 |
| The secret lacks the key, or its value there is empty, `null`, an object or an array | Returns 0 |
| 403: the token is invalid or not allowed to read the path | Throws `HttpRequestException` |
| 404 naming an error, such as a mount that doesn't exist | Throws `HttpRequestException` |
| A protected token that won't decrypt | Throws `InvalidOperationException`, without calling Vault |

An `HttpRequestException` carries Vault's status and errors, never the token.

### Retries

A request that fails transiently is retried `RetryCount` times:

- no answer (connection refused or reset, DNS);
- a connection lost mid-response;
- an attempt that took longer than `Timeout`;
- 429, or a 5xx other than 501. Vault answers 503 while sealed or electing a leader.

The first retry waits `RetryDelay`, each after it twice as long, up to 10 seconds, and every wait
adds a random 0-100 ms, so many clients reconnecting after an outage don't retry in lockstep.
Anything else, including the token provider's failures and your own cancellation, isn't retried.

## Asynchronous lookups

`DecryptAsync` and `GetMaxDecryptedLengthAsync` read the response body asynchronously into the same
pinned memory. `Decrypt` blocks the calling thread until Vault answers or `Timeout` passes. Prefer
the async methods in ASP.NET Core; see [Reading asynchronously](index.md#reading-asynchronously).
