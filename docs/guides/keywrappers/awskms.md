---
title: Wrapping keys with AWS KMS
sidebar_label: AWS KMS
sidebar_position: 1
description: Set up a symmetric AWS KMS key as HkdfGuard's key encryption key, grant each role only what it calls, and use it with AwsKmsKeyWrapper.
---

# Wrapping keys with AWS KMS

`AwsKmsKeyWrapper` (package `HkdfGuard.KeyWrapping.AwsKms`) uses one symmetric AWS KMS key as
HkdfGuard's KEK. Every call is a KMS request, authorized by the process's IAM credentials and
recorded in CloudTrail. What all cloud wrappers share is in the [overview](index.md).

## What the wrapper does

- **`GenerateAndWrapAsync`** calls `GenerateDataKeyWithoutPlaintext` for an AES-256 key, so the
  plaintext DEK never leaves KMS on that call. `WrapAsync` calls `Encrypt`; `UnwrapAsync` calls
  `Decrypt`.
- **The key is pinned on every `Decrypt`.** A symmetric KMS ciphertext names its own key. Without the
  pin, a substituted key file wrapped under any other key the principal may use would still be
  revealed.
- **The encryption context** is KMS's additional authenticated data. It's bound into every wrapped
  DEK, required again to reveal it, and can be required by IAM policy.
- **A failed unwrap zeroes your buffer.**

## 1. Create the KMS key

In the AWS console, open **Key Management Service**, **Customer managed keys**, **Create key**, in
the region your application runs in:

| Setting | Choose | Why |
|---|---|---|
| Key type | **Symmetric** | The wrapper uses `SYMMETRIC_DEFAULT`, which only a symmetric key accepts |
| Key usage | **Encrypt and decrypt** | Not HMAC, not key agreement |
| Key material origin | KMS | The default |
| Regionality | Single-Region | Multi-Region only if you must unwrap in another region |
| Alias | Optional, e.g. `alias/myapp-kek` | For finding the key; still give the wrapper the ARN |

- **Key administrators:** the people or role who manage keys, never your application's or
  pipeline's role. Administrators can rewrite the key policy, and so grant themselves `Decrypt`.
- **Clear "Allow key administrators to delete this key".** Deleting the key makes every DEK wrapped
  under it, and all data encrypted under those DEKs, permanently unrecoverable. To retire a key,
  disable it; that can be undone.
- **Key usage permissions:** choose no one. The console's usage statement grants more than HkdfGuard
  uses; grant exactly what each role needs in step 2.

Copy the key's **ARN**, e.g.
`arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`.

:::warning
Never remove the key policy's *Enable IAM User Permissions* statement (the one naming
`arn:aws:iam::<account-id>:root`). Without it IAM policies stop working for the key, and if no other
statement grants administration, only AWS Support can recover it.
:::

## 2. Grant each role only what it calls

| Principal | Actions on the key |
|---|---|
| Release pipeline that creates key files | `kms:Encrypt`, `kms:GenerateDataKeyWithoutPlaintext` |
| Application that only reads key files | `kms:Decrypt` |
| Application that also uses ephemeral keys | `kms:Decrypt`, `kms:GenerateDataKeyWithoutPlaintext` |

Attach an IAM policy like this to each role, with that role's actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Decrypt"],
    "Resource": "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "Condition": {
      "StringEquals": { "kms:EncryptionContext:purpose": "com.example.myapp" }
    }
  }]
}
```

The condition requires the encryption context the wrapper is given in step 4, so a role limited to
`com.example.myapp` can't reveal a DEK wrapped for another application under the same key.

:::danger Give the application `kms:Decrypt` without `kms:Encrypt`
The wrapper pins the key, so a key file wrapped under any *other* key is refused. But anyone who can
call `Encrypt` on *this* key, with the same encryption context, can produce a key file your
application accepts, holding a DEK they chose. Keep `Encrypt` with the pipeline.
:::

## 3. Give the process credentials

`new AmazonKeyManagementServiceClient()` finds credentials and a region through the AWS SDK's default
chain:

| Where the process runs | Use | What the process holds |
|---|---|---|
| ECS or Fargate | A task role | Nothing; the SDK fetches short-lived credentials |
| EKS | EKS Pod Identity, or IAM roles for service accounts | A token AWS rotates |
| EC2 | An instance profile (IMDSv2) | Nothing |
| Outside AWS | IAM Roles Anywhere, through `credential_process` | A certificate and private key, which can live in a TPM or PKCS#11 token |
| A developer machine | A profile from `aws configure` | A long-lived access key for a low-privilege IAM user |

Don't give a deployed process a long-lived access key. The client's region must be the key's region:
set it in the profile, the environment, or the client
(`new AmazonKeyManagementServiceClient(RegionEndpoint.USEast2)`).

## 4. Create the wrapper

```sh
dotnet add package HkdfGuard.KeyWrapping.AwsKms
```

```csharp
using Amazon.KeyManagementService;
using HkdfGuard.KeyWrapping.AwsKms;

using var kms = new AmazonKeyManagementServiceClient();
var wrapper = new AwsKmsKeyWrapper(kms,
    keyId: "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    encryptionContext: new Dictionary<string, string> { ["purpose"] = "com.example.myapp" });
```

- **Use the key ARN, not an alias.** `Decrypt` resolves an alias when it's called, so re-pointing the
  alias makes every DEK wrapped under the old key unreadable. KMS's automatic key rotation keeps the
  ARN, so you can turn it on with no change here.
- **Use the same encryption context** on every wrapper that handles one application's key files.
  CloudTrail logs it in plain text, so it must never hold a secret.
- **The wrapper doesn't dispose the client.** Keep the client alive as long as anything uses the
  wrapper, including a key ring's background refresh.
- A fourth argument, `keyFileTrust`, trusts a deployer account; see
  [Where key files can live](index.md#where-key-files-can-live).

## 5. Create key files

There's no `hkdfguard wrap` for KMS. The pipeline creates key files with the wrapper, running as the
pipeline role. KMS generates the DEK, so its plaintext never reaches the pipeline:

```csharp
using HkdfGuard.Abstractions;

var wrapped = new byte[WrappedKeyLimits.MaxBytes];
int length = await wrapper.GenerateAndWrapAsync(wrapped);
await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
```

### Wrapping a pipeline key

If the pipeline also encrypts configuration secrets under the new key with
`AesGcmPipelineDataProtector`, wrap that protector's key, and zero the copy:

```csharp
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;

using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 1);
// ... protector.Encrypt(value, "ConnectionStrings:Admin") for each configuration secret ...

var dek = GC.AllocateArray<byte>(32, pinned: true);
try
{
    if (!Convert.TryFromBase64Chars(protector.GetKeyAsBase64(), dek, out var dekLength) || dekLength != dek.Length)
        throw new InvalidOperationException("The pipeline key isn't 32 bytes.");

    var wrapped = new byte[WrappedKeyLimits.MaxBytes];
    int length = await wrapper.WrapAsync(dek, wrapped);
    await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
}
finally
{
    CryptographicOperations.ZeroMemory(dek);
}
```

The same code works with the Azure and Google wrappers. Write key files only where
[the wrapper will trust them](index.md#where-key-files-can-live).

## 6. Use it in a key ring

```csharp
await using var ring = await new KeyRingBuilder()
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(wrapper)
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(300)
    .WithKeyFile(version: 1, pathToFile: @"C:\HkdfGuardKeys\myapp\v1.key")
    .BuildAsync();
```

With dependency injection, register the client for the application's lifetime:

```csharp
var kms = new AmazonKeyManagementServiceClient();
builder.Services.AddSingleton<IAmazonKeyManagementService>(kms);

await builder.Services.AddKeyRingAsync(ring => ring
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(new AwsKmsKeyWrapper(kms, keyArn,
        new Dictionary<string, string> { ["purpose"] = "com.example.myapp" }))
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(300)
    .WithKeyFile(version: 1, pathToFile: @"C:\HkdfGuardKeys\myapp\v1.key"));
```

`BuildAsync` and `AddKeyRingAsync` call KMS once per key, so the application fails to start if KMS
can't be reached or refuses the key. An ephemeral key (`.WithEphemeralKey(version: 1)`) is generated
by KMS with `GenerateDataKeyWithoutPlaintext` and is lost when the process exits.

Each refresh is one `Decrypt` call; see
[Choosing a refresh interval](index.md#choosing-a-refresh-interval). The AWS free tier covers 20,000
KMS requests a month, and a customer managed key costs about $1 a month on top; see
[AWS KMS pricing](https://aws.amazon.com/kms/pricing/).

## If something goes wrong

Every KMS failure is a `CryptographicException` whose message names KMS's error code, with the AWS
exception as its `InnerException`.

| The message names | Cause | Fix |
|---|---|---|
| `AccessDeniedException` | No IAM permission for this action on this key, or the encryption context doesn't satisfy the policy condition | Step 2: check the action, the `Resource` ARN and the condition |
| `NotFoundException` | The ARN is wrong, or the client is in another region | Copy the ARN again; set the client's region to the key's |
| `IncorrectKeyException` | The key file was wrapped under a different KMS key | Use the key the file was created with |
| `InvalidCiphertextException` | The key file was altered, or the encryption context differs | Restore the file; use the same encryption context |
| `DisabledException` | The key is disabled | Re-enable it |
| `KMSInvalidStateException` | The key is pending deletion | Cancel the deletion right away, within its waiting period |
| `ThrottlingException` | Over the account's KMS quota | Lengthen `KeyRefreshInterval`, or ask AWS for a higher quota |
| `Unable to get IAM security credentials` or similar | The SDK found no credentials | Step 3 |

Reading a key file fails before KMS is called:

| You see | Cause | Fix |
|---|---|---|
| `UnauthorizedAccessException` ... `is not trusted` | The file or a folder above it is owned, or modifiable, by an untrusted account; the message names it | Fix the folder's permissions, or trust the deployer with `KeyFileTrust` |
| `UnauthorizedAccessException` ... `UNC or device path` or `drive` | The file isn't on a local fixed drive | Move it to a local drive |
| `UnauthorizedAccessException` ... `it opens` | The path runs through a link, junction or substituted drive | Configure the full, real path |
| `InvalidDataException` ... `unwrapped` | The file looks like a plaintext key | Treat the key as exposed: replace it |
| `InvalidDataException` ... `empty` or `larger than` | It isn't a key file | Check the path |
| `IOException` | Another process has the file open for writing | Let the deployment finish writing it |
| `ArgumentException` naming `KeyFileTrust` | A listed SID isn't valid, or is a group everyone is in | List the deployer's own account or group |

The Azure and Google wrappers read key files the same way, and fail the same way.
