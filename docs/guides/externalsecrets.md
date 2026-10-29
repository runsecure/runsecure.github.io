---
title: External secrets
sidebar_position: 5
description: Create, fingerprint, pin and deliver the key for HkdfGuard's Linux external-secret provider, where the KEK is a P-256 private key your platform mounts as a file.
---

# External secrets

On Linux, a service's KEK can be a file your platform delivers: a Kubernetes Secret, a Vault Agent
sink, a Docker Swarm secret, or a CSI Secrets Store volume. This is the **external-secret**
provider. It suits containers and hosts with no TPM or HSM.

The file *is* the KEK: a P-256 private key. HkdfGuard never creates or writes it. You generate it,
record its fingerprint and pin that in the policy, your platform stores and delivers the key, and
`hkdfguard provision` checks that what arrived is the key you made.

:::warning Know what you're trading
A TPM or HSM key never leaves its hardware. An external secret is loaded into your application's
memory, and the key agreement runs there. Its protection level is `external`: it is exactly as
safe as the platform that stores and delivers it. Prefer a TPM or HSM wherever the host has one.
:::

## 1. Generate the key

Use **DER**, generated with OpenSSL, on a trusted admin machine, in a private directory:

```sh
( umask 077
  openssl genpkey -algorithm EC \
      -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
      -outform DER -out com.company.orders )
```

- **`umask 077`** makes the file owner-only (`0600`) from the moment it's written.
- **`ec_param_enc:named_curve`** records the curve by name, `prime256v1`. The provider requires a
  DER key to name P-256. OpenSSL 3 does this by default, but LibreSSL, the `openssl` macOS ships,
  does not: without the option it writes the curve's full explicit parameters, a 364-byte key the
  provider refuses. Keep the option, so the command works with every `openssl`.
- **Name the file after the service.** The provider looks for the file named exactly like the
  service, `com.company.orders`.

LibreSSL writes SEC1 DER, 121 bytes. OpenSSL 3 writes PKCS#8 DER, 138 bytes. The provider accepts
both.

### Formats the provider accepts

| Format | Accepted | Notes |
|---|---|---|
| SEC1 DER (`ECPrivateKey`) | Yes | What LibreSSL's `genpkey -outform DER` writes |
| PKCS#8 DER (`PrivateKeyInfo`) | Yes | What OpenSSL 3's `genpkey -outform DER` writes |
| 32 raw bytes | Yes, but use DER | A big-endian P-256 private scalar. OpenSSL can't read a bare scalar, so it has no simple fingerprint before it is delivered. |
| PEM (`-----BEGIN ... KEY-----`) | **No** | Convert it first: `openssl pkey -in key.pem -outform DER -out com.company.orders` |
| Base64 text of any of these | **No** | The mounted file must hold the binary bytes |
| DER with explicit curve parameters | **No** | Regenerate it with `ec_param_enc:named_curve` |
| Any curve other than P-256 | **No** | |

The bytes are used exactly as stored, with nothing trimmed. A raw key with a trailing newline is
33 bytes, so it is neither a raw key nor DER, and is refused.

## 2. Check it, and compute its fingerprint

Check that the file is a P-256 private key:

```sh
openssl pkey -inform DER -in com.company.orders -noout -text | grep -E 'Private-Key|NIST CURVE'
# Private-Key: (256 bit)
# NIST CURVE: P-256
```

The `grep` keeps the private key's bytes out of your terminal.

Then compute its **fingerprint**, on the same machine, before the key goes anywhere:

```sh
openssl pkey -inform DER -in com.company.orders -pubout -outform DER \
    | tail -c 65 | sha256sum | cut -d' ' -f1
```

The output is 64 hex characters. On macOS, use `shasum -a 256` in place of `sha256sum`. Record it
with the service's deployment records: you pin it in the policy in the next step, and every later
check compares against it. [Fingerprints](#fingerprints) explains the value and the other places
it appears.

## 3. Pin the fingerprint in the policy

:::note Newer than 0.9.0
Fingerprint pinning for external secrets arrives in the release after `0.9.0`. The policy refuses
settings it doesn't know, so on a `0.9.0` host these settings make the whole policy invalid, and
every call fails (-9). Upgrade first.
:::

The [file rules](#file-rules) limit who could have written the key: root, the service's user, or
anything else that mounts the same volume read-write, such as a secrets sidecar or a shared
`emptyDir`. They can't tell whether the key is the one *you* generated. Any of those writers could
put a valid key of its own in the mount before the real one arrives, and the library would use it.

**Pinning closes that gap.** List each service's fingerprint in `/etc/hkdfguard/policy.toml`, and
the provider refuses any other key for that service:

```toml
[selection]
mode = "require"
provider = "external-secret"

[external_secret]
dir = "/run/secrets/hkdfguard"
require_pinned_keys = true           # a service with no pin has no KEK here

[external_secret.pinned_keys]
"com.company.orders"   = "c5e2c5e5a5d7dea5c975872d137e02049a67c42cf2b71a3a430000dad3b0dbb0"
"com.company.payments" = ["<old 64 hex chars>", "<new 64 hex chars>"]   # a list while rotating
```

- **A key whose fingerprint isn't pinned for its service is refused**, as an error, so the library
  never moves on to another provider.
- **`require_pinned_keys = true`** makes the pins an allowlist: a service not listed has no KEK.
  Without it, services you haven't pinned work as before. Set it in production.
- **Quote service names**, as in `[tpm.pinned_names]`. Unquoted dots would make nested tables.
- **The fingerprint isn't secret.** It can live in the policy wherever you keep and review it.
- A pin that isn't 64 hex characters, an empty list, or a service listed twice makes the policy
  invalid.

## 4. Deliver it

The provider reads `dir/service-name`. `dir` is `external_secret.dir` in the policy. When the
policy doesn't set one, it is the first of these that exists:

```text
/var/run/secrets/hkdfguard
/run/secrets/hkdfguard
/vault/secrets/hkdfguard
/mnt/secrets-store/hkdfguard
```

Name it in the policy, as above.

### File rules

The provider refuses the file, with an error rather than "not provisioned", unless:

- **it is owner-only:** owned by root or the service's user, mode `0400` or `0600`. A root-owned
  file may also be readable by its group, `root:group 0440`, which is how a non-root service reads
  it. Never by others.
- **it is a regular file.** Symbolic links are followed, as Kubernetes Secret volumes need, but
  only while they stay inside the mount.
- **nobody else can write the mount:** the mount directory and every directory above it must be
  owned by root or the service's user, and not writable by group or others. Nothing under `/tmp`,
  `/var/tmp` or `/dev/shm`. A **read-only** mount is the one exception, which is why a Kubernetes
  Secret volume, mode `1777` but read-only, passes.

A file that is present but breaks a rule is always an error, so a broken mount never falls through
to a weaker provider.

### Settings per platform

| Platform | Setting |
|---|---|
| Kubernetes `Secret` volume | `defaultMode: 0400`. A non-root pod also sets `fsGroup`, and the kubelet then makes the file `root:fsGroup 0440`. |
| Vault Agent template or sink | `perms = "0400"` |
| Docker Swarm secret | `mode: 0400`. The default, `0444`, is refused. |
| CSI Secrets Store | `defaultMode`, or the file permission, in the `SecretProviderClass` |

### Kubernetes

Create the Secret from the DER file. `kubectl` base64-encodes it into the manifest, and the
volume gives back the exact bytes:

```sh
kubectl create secret generic hkdfguard-orders --from-file=com.company.orders=./com.company.orders
```

Never put the key under `stringData:`, which holds text, not bytes. Mount the Secret on its own:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    fsGroup: 10001            # a non-root pod reads the root-owned file through its group
  volumes:
    - name: hkdfguard-kek
      secret:
        secretName: hkdfguard-orders
        defaultMode: 0400     # the kubelet makes it root:10001 0440 with fsGroup set
  containers:
    - name: orders
      volumeMounts:
        - name: hkdfguard-kek
          mountPath: /run/secrets/hkdfguard
          readOnly: true
```

Keep **one Secret per service**, mounted only by the pods meant to hold it. Any process that can
read the file can unwrap that service's DEKs. With pinning on, also check every container that
mounts the volume read-write: each one is a writer the pin protects you from.

## 5. Provision

On the host or in the container, run `provision` for the service. With an external secret it
creates nothing: it reads the file, checks it against the file rules and its pin, and prints the
KEK's fingerprint.

```sh
sudo hkdfguard provision -sn com.company.orders
# KEK already provisioned for service "com.company.orders"; verified, nothing to do
# fingerprint: c5e2c5e5a5d7dea5c975872d137e02049a67c42cf2b71a3a430000dad3b0dbb0 -- confirm it matches ...
```

With `require_pinned_keys` on and no pin for the service, `provision` refuses, and prints the policy
line for the key that is **mounted now**:

```text
error: ... external_secret.require_pinned_keys is set and service "com.company.orders" has no pinned
key. The key mounted for it has fingerprint 661d...5085 ...
  [external_secret.pinned_keys]
  "com.company.orders" = "661d707d5c1ae3228a0777a9a8a460671a38d35fa577d9d16246519fa15a5085"
```

That line tells you which key is in the mount, not which key you generated. Use it only to confirm
the fingerprint you computed in step 2, never in place of it.

Then wrap DEKs and use them exactly as with any other provider: see the
[Linux guide](gettingstarted/linux.md#6-wrap-a-dek-into-a-key-file).

## 6. Back it up, clean up, and rotate

- **Back it up in your secret manager.** It is the KEK. If it is lost or changed, every DEK wrapped
  under it is unrecoverable, and payloads wrapped earlier fail with a fingerprint mismatch (-16).
- **Delete the working copy** from the admin machine once it is delivered and backed up. Overwriting
  a file with `shred` doesn't reliably erase it on SSDs or copy-on-write filesystems, so generate
  it somewhere you trust in the first place: an encrypted disk, or a RAM-backed directory.
- **To rotate a service's key**, generate the new key and compute its fingerprint, then:
  1. add the new fingerprint to the service's pin, as a list beside the old one;
  2. deliver the new key;
  3. re-wrap the DEKs the service still needs under it. A DEK wrapped under the old key stops
     unwrapping as soon as the new key replaces it in the mount;
  4. remove the old fingerprint.

  Alternatively, provision a new, versioned service name, such as `com.company.orders.v2`, which
  lets the old and new keys exist side by side. `hkdfguard retire` refuses external-secret keys:
  remove an old one where your platform manages it, once nothing needs it.

## Fingerprints

A KEK's **fingerprint** is the SHA-256 of its public key in uncompressed form,
`SHA-256(0x04 || X || Y)`, as 64 hex characters. It isn't secret. It names *which* key a service
uses, so it lets you check, at every step, that the key is the one you made:

| Where | How |
|---|---|
| The key you generated | Compute it with OpenSSL, below |
| The key the policy allows | `[external_secret.pinned_keys]` |
| The KEK the host actually uses | `hkdfguard provision` prints it |
| The KEK a DEK was just wrapped under | `hkdfguard wrap` prints it |
| The KEK a key file was wrapped under | The last 32 bytes of the key file |

All of these agree for the same key. Record the first; pin it; compare the others with it.

### From a DER key file

```sh
openssl pkey -inform DER -in com.company.orders -pubout -outform DER \
    | tail -c 65 | sha256sum | cut -d' ' -f1
```

`-pubout` writes the public key as a SubjectPublicKeyInfo structure, which ends with the 65-byte
uncompressed point `0x04 || X || Y`. `tail -c 65` keeps just that point, and its SHA-256 is the
fingerprint, ready to paste into `pinned_keys`.

### From a raw 32-byte key

Use DER for new keys. If you already have a raw key, OpenSSL can't read it directly, so give it a
minimal SEC1 wrapper first: the fixed SEC1 prefix, the 32 key bytes, and the P-256 curve's name:

```sh
{ printf '\x30\x31\x02\x01\x01\x04\x20'; cat com.company.orders; printf '\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07'; } \
    | openssl ec -inform DER -pubout -conv_form uncompressed -outform DER \
    | tail -c 65 | sha256sum | cut -d' ' -f1
```

The pipe keeps the wrapped copy out of any file.

### From a key in a Kubernetes Secret

Read it back from the cluster, to check what was actually stored:

```sh
kubectl get secret hkdfguard-orders -o jsonpath='{.data.com\.company\.orders}' | base64 -d \
    | openssl pkey -inform DER -pubout -outform DER \
    | tail -c 65 | sha256sum | cut -d' ' -f1
```

This decodes the private key in a pipeline on your machine, so run it only where you would handle
the key anyway.

### From a wrapped key file

A Linux key file ends with the fingerprint of the KEK it was wrapped under, so you can check a key
file without the key:

```sh
tail -c 32 /etc/myapp/keys/myapp.v1.key | xxd -p -c 32
```

It must match the service's fingerprint. If it doesn't, the key file was wrapped under a different
KEK, and unwrapping it fails with status -16.

### Pin it when wrapping, too

The policy pin stops the host from *using* the wrong key. `wrap --fingerprint` stops a deployment
from *committing* a DEK to the wrong key: it writes nothing unless the DEK was sealed to the key
you name:

```sh
head -c 32 /dev/urandom | base64 | sudo hkdfguard wrap -kf /etc/myapp/keys/myapp.v1.key \
    -sn com.company.orders --dek-stdin -fp c5e2c5e5a5d7dea5c975872d137e02049a67c42cf2b71a3a430000dad3b0dbb0
# fingerprint: c5e2...dbb0 (confirmed)
```

On a mismatch it reports `fingerprint mismatch for service "com.company.orders": the service's KEK
is ..., not ...`, and writes nothing.

## Troubleshooting

`hkdfguard provision` names the reason for every refusal:

| Message contains | Cause | Fix |
|---|---|---|
| `has fingerprint ..., which is not the one pinned in policy` | The mounted key isn't the one `pinned_keys` names. Something else wrote the mount, or the key was rotated without its fingerprint being added first. | Check every container that mounts the volume read-write. Pin a new fingerprint only once you've confirmed where the key came from. |
| `require_pinned_keys is set and service ... has no pinned key` | The service isn't in `[external_secret.pinned_keys]` | Compare the printed fingerprint with the one you computed in step 2, then add the line |
| `pinned_keys[...] is not valid hex`, or `is ... bytes, expected 32` | A pin isn't 64 hex characters | Paste the fingerprint exactly as computed |
| `not a valid P-256 key (expected 32 raw bytes, PKCS#8 DER or SEC1 DER; PEM must be converted to DER)` | The file is PEM, base64 text, a raw key with a trailing newline, DER with explicit curve parameters, or a key for another curve | Regenerate it as in [step 1](#1-generate-the-key), or convert PEM to DER |
| `permissions too broad` | The file is readable or writable by group or others, beyond `root:group 0440` | Set the platform's mode, as in [Settings per platform](#settings-per-platform) |
| `invalid raw external KEK scalar` | A raw 32-byte value outside P-256's range | Generate a new key, as DER |
