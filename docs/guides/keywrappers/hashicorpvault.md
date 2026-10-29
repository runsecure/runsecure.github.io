---
title: Wrapping keys with HashiCorp Vault transit
sidebar_label: HashiCorp Vault
sidebar_position: 4
description: Set up a HashiCorp Vault transit key as HkdfGuard's key encryption key, grant each role only the paths it calls, and use it with HashiCorpVaultTransitKeyWrapper.
---

# Wrapping keys with HashiCorp Vault transit

`HashiCorpVaultTransitKeyWrapper` (package `HkdfGuard.KeyWrapping.HashiCorpVault`) uses one key in a
Vault **transit** secrets engine as HkdfGuard's KEK. The key never leaves Vault. What all cloud and
network wrappers share is in the [overview](index.md).

Use it when your applications already authenticate to Vault, or run where no cloud KMS is
available, and you want key access controlled by Vault policy and recorded in Vault's audit log.

Like the [Vault cache](../caches/hashicorpvault.md), it uses no SDK. It calls Vault's HTTP API
itself and depends only on `HkdfGuard.Abstractions` and `HkdfGuard.SecureFile`.

## What the wrapper does

- **`WrapAsync`** calls `transit/encrypt/{key}` and **`UnwrapAsync`** calls `transit/decrypt/{key}`.
- **`GenerateAndWrapAsync`** depends on whether you give a context:
  - **without one**, it calls `transit/datakey/wrapped/{key}`, so Vault generates the DEK and returns
    it wrapped only. The plaintext DEK never leaves Vault on that call.
  - **with one**, it generates the DEK in your process and wraps it with `encrypt`, because
    `datakey/wrapped` ignores `associated_data`. The DEK is zeroed once wrapped.
- **The key is pinned by its path** on every request. A key file can't point the wrapper at another
  key.
- **The context is bound as Vault's `associated_data`**, and must be given again, exactly, to
  reveal a DEK. If Vault answers that it ignored a parameter, as a Vault too old for
  `associated_data` does, the call fails: a context is never silently dropped.
- **A failed unwrap zeroes your buffer.**

A wrapped DEK is Vault's ciphertext exactly as Vault returns it, `vault:v1:...`, about 89 bytes of
ASCII.

## 1. Create the transit key

As a Vault operator, enable the engine (once) and create the key:

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-kek type=aes256-gcm96
```

| Setting | Choose | Why |
|---|---|---|
| `type` | `aes256-gcm96` (the default), `aes128-gcm96` or `chacha20-poly1305` | The context needs an AEAD key |
| `derived` | `false` (the default) | A derived key needs a `context` parameter on every request, which the wrapper doesn't send. A key that *isn't* derived silently ignores that parameter, which is why the wrapper binds its context as `associated_data` instead |
| `exportable` | `false` (the default) | Nothing here needs the key material out of Vault |
| `deletion_allowed` | `false` (the default) | Deleting the key makes every DEK wrapped under it unreadable, for good |

### Rotation

Rotate with `vault write -f transit/keys/myapp-kek/rotate`. New DEKs are wrapped under the latest
version. Existing key files keep revealing as long as their version is at or above the key's
`min_decryption_version`, so don't raise that until every key file has been rewrapped.

## 2. Grant each role only the paths it calls

Give **`update`, never `create`**, on exactly the paths each role uses.

:::danger Why not `create`
With `create`, `transit/encrypt/{name}` makes a new key when none exists. A mistyped key name would
then quietly wrap DEKs under a brand-new key instead of failing.
:::

The release pipeline, which creates key files:

```hcl
path "transit/encrypt/myapp-kek"         { capabilities = ["update"] }
path "transit/datakey/wrapped/myapp-kek" { capabilities = ["update"] }
```

The application, which only reads existing key files:

```hcl
path "transit/decrypt/myapp-kek" { capabilities = ["update"] }
```

Add `transit/encrypt/myapp-kek` (and `transit/datakey/wrapped/myapp-kek`) to the application only if
it generates ephemeral keys at startup. Anyone who can call `encrypt` on the key, with the same
context, can create a key file your application accepts.

```bash
vault policy write myapp-kek-pipeline pipeline.hcl
vault policy write myapp-kek-app app.hcl
```

Then bind each policy to the auth method its role logs in with: AppRole, Kubernetes, a certificate,
or a cloud IAM role.

## 3. Give the process a token

Every request is made with a token from an `IVaultTokenSource`. Logging in, renewing and replacing
the token is the source's job, so any auth method can sit behind the wrapper.

The source copies the token into a pinned buffer the wrapper owns, rather than returning it as a
string, and the wrapper zeroes that buffer once the request has been sent. The token is asked for
once per wrap, unwrap or generate, not once per retry.

### A token you already hold

`StaticVaultTokenSource` holds a token issued elsewhere, such as `VAULT_TOKEN` or a Vault Agent sink
file, in pinned memory, and zeroes it when disposed:

```csharp
using HkdfGuard.KeyWrapping.HashiCorpVault;

using var token = new StaticVaultTokenSource(Environment.GetEnvironmentVariable("VAULT_TOKEN"));
```

Nothing renews it. Once it expires or is revoked, every request fails with 403. For a long-running
service, prefer a **Vault Agent on loopback** with `use_auto_auth_token`, which renews the token
itself, or implement `IVaultTokenSource` over your own auth method:

```csharp
public sealed class MyVaultLogin : IVaultTokenSource
{
    public async ValueTask<int> CopyTokenAsync(Memory<char> destination, CancellationToken cancellationToken)
    {
        // Log in or renew as needed, then copy the token into destination and return its length.
        // destination holds up to HashiCorpVaultTransitKeyWrapper.MaxTokenLength characters.
        return await CopyCurrentTokenAsync(destination, cancellationToken);
    }
}
```

A token that is empty, or isn't printable ASCII without spaces, fails the call.

:::note Not the cache's token provider
The [Vault cache](../caches/hashicorpvault.md) takes an `IVaultTokenProvider`, which hands over a
token encrypted by the key ring. A key wrapper runs *before* there is a key ring, so it can't, and
uses `IVaultTokenSource` instead.
:::

## 4. Create the wrapper

```sh
dotnet add package HkdfGuard.KeyWrapping.HashiCorpVault
```

```csharp
using HkdfGuard.KeyWrapping.HashiCorpVault;

using var wrapper = new HashiCorpVaultTransitKeyWrapper(
    new Uri("https://vault.example.com:8200"),
    keyName: "myapp-kek",
    tokenSource: token,
    context: "com.example.myapp");
```

- **The address must be `https`**, except on a loopback address (a local Vault Agent or dev server):
  every request carries a token, and wrap and unwrap carry plaintext DEKs. A path is kept as a
  prefix, for Vault behind a reverse proxy.
- **The context** isn't secret and must not hold one. Use the same value on every wrapper that
  handles one application's key files. Choose a context for the binding, or none to have Vault
  generate DEKs.
- **Dispose the wrapper** to release its connections, but only once nothing uses it, including a key
  ring's background refresh. It doesn't dispose the token source or a handler you supply.
- Optional arguments: `keyFileTrust` trusts a deployer account (see
  [Where key files can live](index.md#where-key-files-can-live)), and `options` is below.

### Options

`HashiCorpVaultTransitKeyWrapperOptions`:

| Option | Default | What it does |
|---|---|---|
| `MountPath` | `transit` | Where the transit engine is mounted, e.g. `transit/team-a` |
| `Namespace` | none | Sent as `X-Vault-Namespace`, for Vault Enterprise |
| `Timeout` | 30 seconds | How long one attempt may take |
| `RetryCount` | 3 | Retries for a transient failure, 3 to 10 |
| `RetryDelay` | 200 ms | The wait before the first retry, doubling each time, up to 10 seconds, plus up to 100 ms of jitter |
| `HttpMessageHandler` | the wrapper's own | Sends every request, to trust a private CA or use a proxy. Not disposed by the wrapper |
| `AllowRedirects` | `false` | Accepts a handler that follows redirects |

A request that gets no answer, loses its connection, times out, or is answered 429 or a 5xx other
than 501 is retried. Vault answers 503 while sealed or electing a leader.

The wrapper's own handler follows no redirects, which would carry the token elsewhere. A handler you
supply that follows them is refused unless you set `AllowRedirects`, so turn redirects off:

```csharp
var options = new HashiCorpVaultTransitKeyWrapperOptions
{
    MountPath = "transit/team-a",
    Namespace = "team-a/prod",
    HttpMessageHandler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        SslOptions = { RemoteCertificateValidationCallback = ValidateAgainstPrivateCa },
    },
};
```

## 5. Create and use key files

The pipeline creates key files with the wrapper, logged in as the pipeline role:

```csharp
using HkdfGuard.Abstractions;

var wrapped = new byte[WrappedKeyLimits.MaxBytes];
int length = await wrapper.GenerateAndWrapAsync(wrapped);
await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
```

To wrap a key the pipeline already holds, such as an `AesGcmPipelineDataProtector`'s, use
`WrapAsync` as in [Wrapping a pipeline key](awskms.md#wrapping-a-pipeline-key). Write key files only
where [the wrapper will trust them](index.md#where-key-files-can-live).

Then use the wrapper like any other:

```csharp
await using var ring = await new KeyRingBuilder()
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(wrapper)
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(300)
    .WithKeyFile(version: 1, pathToFile: @"C:\HkdfGuardKeys\myapp\v1.key")
    .BuildAsync();
```

`BuildAsync` calls `decrypt` once per key, so the application fails to start if Vault can't be
reached or refuses the key. Each refresh is one `decrypt`, recorded in Vault's audit log; see
[Choosing a refresh interval](index.md#choosing-a-refresh-interval).

## If something goes wrong

Every Vault failure is a `CryptographicException` whose message gives Vault's status and errors,
with an `HttpRequestException`, `IOException` or timeout as its `InnerException`. A token source's
own failure propagates as it is. Reading a key file fails as described for
[AWS KMS](awskms.md#if-something-goes-wrong).

| The message names | Cause | Fix |
|---|---|---|
| `403 Forbidden` ... `permission denied` | The policy doesn't grant `update` on this path, or the token is invalid or expired | Step 2's paths; renew or replace the token |
| `400 BadRequest` ... `encryption key not found` | No key by that name in this mount or namespace | Check the key name, `MountPath` and `Namespace` |
| `400 BadRequest` ... `cipher: message authentication failed` | The key file was altered, wrapped under another key, or with another context | Restore it; use the key and context it was made with |
| `400 BadRequest` ... `missing 'context' for key derivation` | The key is derived | Create a key with `derived=false` and rewrap |
| `400 BadRequest` ... `disallowed by policy (too old)` | The file's key version is below `min_decryption_version` | Lower it, or rewrap the file |
| `ignored a parameter` | This Vault doesn't support `associated_data` | Upgrade Vault (the integration tests run against 1.19) |
| `503 ServiceUnavailable` | Vault is sealed or electing a leader, beyond the retries | Unseal Vault; check its HA status |
| `no answer within` | No answer within `Timeout`, on every attempt | Check the address and network path |
| `InvalidOperationException` ... `token source` | The source supplied no token, or one with spaces or non-ASCII characters | Check what the source reads |
