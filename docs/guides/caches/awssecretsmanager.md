---
title: Caching AWS Secrets Manager secrets
sidebar_label: AWS Secrets Manager
sidebar_position: 2
description: Read secrets from AWS Secrets Manager on demand with AwsSecretsManagerSecretCache, holding them in memory only as ciphertext under your key ring.
---

# Caching AWS Secrets Manager secrets

`AwsSecretsManagerSecretCache` (package `HkdfGuard.Cache.AwsSecretsManager`) reads secrets from AWS
Secrets Manager on demand and caches them encrypted under your key ring. How every cache works is
in the [overview](index.md); this page covers what's particular to Secrets Manager.

## 1. Grant the application read access

The cache calls only `GetSecretValue`, for the `AWSCURRENT` version of the one secret asked for. It
never calls `ListSecrets` or `BatchGetSecretValue`. Grant exactly that, on exactly the secrets the
application reads:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "arn:aws:secretsmanager:us-east-2:111122223333:secret:prod/myapp/*"
  }]
}
```

If the secrets are encrypted under a customer managed KMS key rather than `aws/secretsmanager`,
the application also needs `kms:Decrypt` on that key.

Credentials come from the AWS SDK's default chain unless you pass your own. Deployed, use a role:
an ECS task role, EKS Pod Identity or IAM roles for service accounts, an EC2 instance profile, or
IAM Roles Anywhere outside AWS. Don't give a deployed process a long-lived access key.

## 2. Create the cache

```sh
dotnet add package HkdfGuard.Cache.AwsSecretsManager
```

```csharp
using Amazon;
using Amazon.SecretsManager;
using HkdfGuard.Cache.AwsSecretsManager;

using var secrets = new AwsSecretsManagerSecretCache(ring,
    new AmazonSecretsManagerConfig
    {
        RegionEndpoint = RegionEndpoint.USEast2,
        Timeout = TimeSpan.FromSeconds(10),
    });

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("prod/myapp/Db-Password", buffer); // 0 if the secret doesn't exist
```

- **Both config and credentials are optional.** `new AwsSecretsManagerSecretCache(ring)` takes the
  region and credentials from the SDK's defaults. Pass an `AWSCredentials` as the third argument to
  use your own.
- **Set timeouts on the config.** The AWS SDK is async-only and `Decrypt` is synchronous, so a
  first lookup blocks until AWS answers. Use `DecryptAsync` in async code.
- **Dispose the cache.** It owns its Secrets Manager client. The key ring is yours.

## Names

Look secrets up by **name, not ARN**. A name is 1-512 ASCII letters, digits and `/_+=.@-`; anything
else returns 0 without a call. `AwsSecretsManagerSecretCache.IsValidSecretName` tells you in
advance.

Names match exactly, as Secrets Manager matches them: `prod/Db` and `prod/db` are separate secrets
and separate entries.

### What gets cached

| The secret holds | Cached as |
|---|---|
| A `SecretString` | Its UTF-8 bytes |
| A `SecretString` that is a JSON object (a key/value secret) | Its whole text, and each key as `name#key` |
| A `SecretBinary` | Its bytes, never split into keys |

Secrets Manager's console stores key/value secrets as JSON objects, so `prod/myapp#password` reads
one key of them. See [Secrets holding several keys](index.md#secrets-holding-several-keys).

## Missing secrets and failures

| Secrets Manager answers | The cache |
|---|---|
| `ResourceNotFoundException`, or an empty value | Returns 0, and looks the name up again next time |
| `AccessDeniedException`, a KMS failure, throttling, or no answer | Throws the AWS exception |

A cached value isn't refreshed. After rotating a secret, a new cache instance picks up the new
`AWSCURRENT` version.

## Asynchronous lookups

`DecryptAsync` and `GetMaxDecryptedLengthAsync` call `GetSecretValueAsync` without blocking a thread.
Prefer them in ASP.NET Core; see [Reading asynchronously](index.md#reading-asynchronously).
