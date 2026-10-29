---
title: Secret-store caches
sidebar_label: Overview
sidebar_position: 0
description: Read secrets from Azure Key Vault, AWS Secrets Manager, Google Cloud Secret Manager or HashiCorp Vault on demand, and hold them in memory only as ciphertext under your key ring.
---

# Secret-store caches

A secret-store cache reads secrets from a network secret store and keeps them in memory only as
ciphertext, encrypted under your application's key ring. Your code asks for a secret by name when it
needs it, gets the plaintext into a buffer it owns, and zeroes that buffer when it's done.

There's one cache per store:

| Store | .NET package | Page |
|---|---|---|
| Azure Key Vault (secrets) | `HkdfGuard.Cache.AzureKeyVault` | [Azure Key Vault](azurekeyvault.md) |
| AWS Secrets Manager | `HkdfGuard.Cache.AwsSecretsManager` | [AWS Secrets Manager](awssecretsmanager.md) |
| Google Cloud Secret Manager | `HkdfGuard.Cache.GoogleSecretManager` | [Google Secret Manager](googlesecretmanager.md) |
| HashiCorp Vault (KV version 2 or 1) | `HkdfGuard.Cache.HashiCorpVault` | [HashiCorp Vault](hashicorpvault.md) |

The examples on these pages are C#. The Python library has the same four caches, as
`hkdfguard-cache-azurekeyvault`, `hkdfguard-cache-awssecretsmanager`,
`hkdfguard-cache-googlesecretmanager` and `hkdfguard-cache-hashicorpvault`.

:::note Caches aren't key wrappers
A cache holds *your application's secrets*: connection strings, API keys, passwords. A
[key wrapper](../keywrappers/index.md) holds the *key encryption key* that protects your data
encryption keys. A cache needs a key ring to encrypt under, and that ring needs a key wrapper,
native, cloud or Vault transit. The two are configured separately and can use different services.
:::

## How a cache works

Every cache is an `IProtectedReadOnlyCache`, and all four share one base class, `RemoteSecretCache`
(in `HkdfGuard.Cache`), which owns fetching, caching, encryption, name matching and telemetry.

1. **Nothing is fetched up front.** The first `Decrypt` (or `TryGetMaxDecryptedLength`) for a name
   reads that one secret from the store.
2. **The value is encrypted at once** under the key ring's current key, bound to its name as
   additional authenticated data (AAD), and only the ciphertext is cached. A ciphertext copied to
   another name fails authentication.
3. **Later lookups never call the store.** They decrypt the cached ciphertext into your buffer.
4. **The cache follows key rotation.** Each entry records the key version it was encrypted under,
   and decrypts under that version.

```csharp
Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("Db-Password", buffer); // 0 if the secret doesn't exist
try
{
    Use(buffer[..written]);
}
finally
{
    buffer.Clear();
}
```

Concurrent lookups of the same uncached secret share one fetch. A cached value is never refreshed:
a new secret version is picked up by a new cache instance.

### Least privilege: no listing

No cache ever lists the store. Each reads one secret by name, so the application needs only the
store's "read one secret" permission:

| Store | Permission the application needs |
|---|---|
| Azure Key Vault | **Key Vault Secrets User** role (`get` on secrets) |
| AWS Secrets Manager | `secretsmanager:GetSecretValue` (plus `kms:Decrypt` on a customer managed key that encrypts the secrets) |
| Google Cloud Secret Manager | **Secret Manager Secret Accessor** role (`secretmanager.versions.access`) |
| HashiCorp Vault | `read` on the paths it reads |

### A secret never becomes a string

Every cloud SDK would hand a secret to your process as a `string` (Key Vault, Secrets Manager) or
leave it in a pooled buffer (gRPC, buffered HTTP responses). None of those can be zeroed. So each
cache makes its own client and takes the value out *below* the SDK:

| Store | How the value is captured |
|---|---|
| Azure Key Vault | A pipeline policy reads the response body into pinned memory, takes the value out, and lets `SecretClient` parse a copy with the value blanked |
| AWS Secrets Manager | A pipeline handler ahead of unmarshalling does the same |
| Google Cloud Secret Manager | The protobuf payload is encrypted from the bytes it was deserialized into; those bytes and gRPC's pooled receive buffer are both zeroed |
| HashiCorp Vault | No SDK: the unbuffered HTTP response is read straight into pinned memory |

Every buffer that held a value is zeroed once the value is encrypted. What no library above the
HTTP stack can reach are that stack's own buffers: TLS decryption and socket reads.

For the same reason, don't turn on response-content logging for a cache's client. The Key Vault
cache refuses options that log content; for the others, it's up to you.

## Names, missing secrets and failures

Each store has its own rules for which names it can hold. A name the store can't hold returns 0
**without a call**, so a cache can sit last in a `ProtectedCacheCollection` behind other sources,
such as encrypted configuration, without wasting a round trip on names like
`ConnectionStrings:Admin`.

| Store | Valid names | Matching |
|---|---|---|
| Azure Key Vault | 1-127 ASCII letters, digits and hyphens | Ignoring ASCII case, as Key Vault does |
| AWS Secrets Manager | 1-512 ASCII letters, digits and `/_+=.@-` (names, not ARNs) | Exact |
| Google Cloud Secret Manager | 1-255 ASCII letters, digits, hyphens and underscores | Exact |
| HashiCorp Vault | Path segments of ASCII letters, digits, `-`, `_` and `.`; no `.` or `..` segment | Exact |

A secret that doesn't exist, or is empty, returns 0 and isn't remembered: it's looked up again next
time. Any other failure (access denied, a disabled secret, the store unreachable) throws the
store's own exception, so a misconfiguration is never mistaken for a missing secret. Each store's
page lists exactly what counts as missing.

## Secrets holding several keys

A secret often holds a set of values rather than one: an AWS key/value secret (a JSON object in its
`SecretString`), a JSON object kept in a Key Vault secret or a Google payload by convention, or any
Vault KV secret. Every cache reads one key of such a secret as `secret#key`:

```csharp
// The secret "prod/app" holds {"api-key":"...","user":"svc-app","port":5432}.
int written = secrets.Decrypt("prod/app#api-key", buffer);
written = secrets.Decrypt("prod/app#port", buffer);  // "5432"
written = secrets.Decrypt("prod/app", buffer);       // the whole JSON text
```

The Vault cache is the exception: a Vault secret is always a set of keys, so a name without `#`
reads its default key, `value` unless set. See [HashiCorp Vault](hashicorpvault.md#names).

- **One fetch caches every key.** The first lookup of any key fetches the secret once and caches
  its whole value and every key it holds, each encrypted on its own and bound to its own name.
- **Values are never strings here either.** Each value is unescaped into pinned memory and zeroed
  once encrypted.
- **What's cached:** a string member as its UTF-8 bytes; a number, `true` or `false` as its JSON
  text. `null`, objects, arrays, empty strings, and members whose name isn't a valid key (1-256
  printable ASCII characters other than space, `!` and `#`) are left out.
- **What isn't split:** a value that isn't exactly one JSON object (plain text, an array, malformed
  JSON) is cached whole only. An AWS `SecretBinary` is never split. An object naming a member twice
  is refused with `InvalidDataException`.
- **Keys match exactly**, even in Key Vault, whose secret names ignore case: `App-Login#user` and
  `app-login#user` are the same key, `App-Login#User` is another.

A key the secret doesn't hold returns 0, and costs a fetch each time it's asked for. A later fetch
adds keys that weren't cached yet, but never replaces one that was.

## Reading asynchronously

`Decrypt` and `TryGetMaxDecryptedLength` block until the store answers on a miss. In ASP.NET Core
and other async code, use `DecryptAsync` and `GetMaxDecryptedLengthAsync` instead; they fetch
without blocking a thread:

```csharp
var max = await secrets.GetMaxDecryptedLengthAsync("prod/app#api-key", cancellationToken); // 0 if missing
var buffer = ArrayUtility.AllocatePinned<char>(max);
try
{
    var written = await secrets.DecryptAsync("prod/app#api-key", buffer.AsMemory(), cancellationToken);
    Use(buffer.AsSpan(0, written));
}
finally
{
    ArrayUtility.ZeroMemory(buffer.AsSpan());
}
```

An async method can't take a `Span`, so the plaintext lands in memory you provide. **Pass a pinned
array, never a pooled one, and zero it once used.**

- Synchronous and asynchronous lookups of the same uncached secret share one fetch.
- The cancellation token cancels your lookup's wait, and the fetch itself only if your lookup
  started it. A lookup whose fetch was cancelled by another caller starts a new one rather than
  failing.
- `ProtectedCacheCollection` awaits each source in turn, so a secret-store cache in a collection
  doesn't block either.

## Combining sources

`ProtectedCacheCollection` puts several read-only caches behind one surface, checked in
registration order. Put local, cheap sources first and a secret-store cache last:

```csharp
var secrets = new ProtectedCacheCollection()
    .Add(protectedConfiguration)   // an IProtectedConfigurationRoot: encrypted values from appsettings.json
    .Add(keyVaultCache);           // anything else, fetched on first use
```

Names the store can't hold never reach it, so `ConnectionStrings:Admin` costs nothing at the
Key Vault cache.

## Writing a cache for another store

Another secret store needs only a subclass of `RemoteSecretCache` that says which names it can hold
and reads one secret by name, and, if its client is asynchronous, how to read it without blocking:

```csharp
public sealed class MySecretStoreCache(MyClient client, IKeyRing ring)
    : RemoteSecretCache(ring, SecretNameMatching.Exact)
{
    protected override bool IsValidName(string name) => name.All(char.IsAsciiLetterOrDigit);

    // Hand the value to the sink, or return without doing so if the secret doesn't exist.
    protected override void Fetch(string name, SecretValueSink value)
    {
        if (client.TryGet(name, out var secret))
            value.SetText(secret);
    }

    // Optional: without it, DecryptAsync calls Fetch. Hand values over between awaits.
    protected override async ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        if (await client.GetAsync(name, cancellationToken) is { } secret)
            value.SetText(secret);
    }
}
```

Fetching, `secret#key` splitting, one-fetch-at-a-time, encryption and telemetry all come from the
base class. If your client returns a JSON response body, `SecretJsonBody` takes the secret out of it
into pinned memory and returns the body with the value blanked, for the client to parse.
