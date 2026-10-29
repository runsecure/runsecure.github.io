---
title: Getting started on Linux
sidebar_label: Linux
sidebar_position: 3
description: Install HkdfGuard on Linux, configure a TPM-backed key for your service, wrap your first data encryption key, and use it from your application.
---

# Getting started on Linux

This guide takes one Linux host from nothing to a working setup: the HkdfGuard native library
installed, the host configured to keep keys in its TPM, a key (KEK) provisioned for your
service, a first key file, and your application using it.

New to HkdfGuard? Read the [overview](index.md) first.

:::note Pre-release
Versions `0.9.x` are for pre-release testing. The commands below use `0.9.0` on Ubuntu 24.04
amd64; substitute your version, distribution and architecture.
:::

## Requirements

- **x86_64 (amd64) or aarch64 (arm64).**
- **A supported distribution:** Debian 13, Ubuntu 24.04, RHEL 10 and compatibles (AlmaLinux,
  Rocky), Amazon Linux 2023, SLES 16 or openSUSE Leap 16. HkdfGuard needs the tpm2-tss 4.x
  libraries, so Debian 12, RHEL 9, SLES 15 and Amazon Linux 2 aren't supported.
- **Root**, to install, configure the host and provision keys.
- **A TPM 2.0**, for the setup in this guide. Check with `ls -l /dev/tpmrm0`. A host without one
  can use an HSM or a secret your platform mounts instead; see [Other providers](#other-providers).

## Where keys can live

Linux has four **providers**, from strongest to weakest:

| Provider | Where the KEK lives |
|---|---|
| TPM 2.0 (`tpm2`) | Derived inside the TPM on demand. The private key never leaves the chip, and nothing is stored on it. |
| PKCS#11 (`pkcs11`) | Generated and kept on an HSM or token |
| External secret (`external-secret`) | A root-owned file your platform delivers: a Kubernetes Secret, a Vault Agent sink, a systemd credential |
| Ephemeral (`ephemeral`) | Process memory only, lost when the process exits. Development and tests only. |

With no policy file, the library tries the TPM, then PKCS#11, then an external secret, and uses
the first one that is set up. It never uses ephemeral keys unless a policy names them. It moves
on only when a provider is *absent*. A provider that is present but failing (wrong
permissions, a wrong PIN) ends the call with an error, rather than quietly protecting new keys
with a weaker one.

## 1. Download and verify

Download from the [Releases page](https://github.com/runsecure/hkdfguard-native-linux/releases)
the tarball for your distribution, `SHA256SUMS`, and the `.sigstore.json` provenance bundle:

| File | Contents |
|---|---|
| `hkdfguard-0.9.0-ubuntu24.04-amd64.tar.gz` | The packages for one distribution: `debian`, `ubuntu24.04`, `el10`, `al2023` or `sles16`, for `amd64` or `arm64` |
| `hkdfguard-0.9.0-linux-amd64.tar.gz` | The standalone library, tool and header, for distributions without a package |
| `SHA256SUMS` | Checksums of every tarball |
| `hkdfguard-0.9.0.sigstore.json` | The signed build-provenance attestation |

Verify before installing:

```sh
sha256sum --check --ignore-missing SHA256SUMS

gh attestation verify hkdfguard-0.9.0-ubuntu24.04-amd64.tar.gz \
    --repo runsecure/hkdfguard-native-linux
```

A successful check proves the file was built by the project's release workflow from the
tagged commit. Without network access to GitHub, add `--bundle hkdfguard-0.9.0.sigstore.json`.
To verify with [cosign](https://docs.sigstore.dev/cosign/) instead, which needs no GitHub
account:

```sh
v=0.9.0
cosign verify-blob-attestation --new-bundle-format \
    --bundle "hkdfguard-$v.sigstore.json" \
    --type https://slsa.dev/provenance/v1 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "https://github.com/runsecure/hkdfguard-native-linux/.github/workflows/release.yml@refs/tags/v$v" \
    "hkdfguard-$v-ubuntu24.04-amd64.tar.gz"
```

## 2. Install

Install the library and the tool together; the tool requires the same version of the library.

**Debian and Ubuntu**

```sh
tar -xzf hkdfguard-0.9.0-ubuntu24.04-amd64.tar.gz
cd hkdfguard-0.9.0-ubuntu24.04-amd64
sudo apt install ./libhkdfguard1_*.deb ./hkdfguard_*.deb
```

Keep the `./`: without it, apt looks the names up in its repositories.

**RHEL 10 and compatibles, Amazon Linux 2023**

```sh
tar -xzf hkdfguard-0.9.0-el10-amd64.tar.gz
cd hkdfguard-0.9.0-el10-amd64
sudo dnf install ./hkdfguard-libs-0*.rpm ./hkdfguard-0*.rpm
```

**SLES 16 and openSUSE Leap 16**

```sh
tar -xzf hkdfguard-0.9.0-sles16-amd64.tar.gz
cd hkdfguard-0.9.0-sles16-amd64
sudo zypper install --allow-unsigned-rpm ./libhkdfguard1-*.rpm ./hkdfguard-0*.rpm
```

The packages aren't signed individually: their integrity comes from the checksums and the
attestation you verified above.

The packages install:

- the library, `libhkdfguard.so.1`;
- the `hkdfguard` tool at `/usr/bin/hkdfguard`, with a man page;
- an empty `/etc/hkdfguard`;
- an example policy at `/usr/share/hkdfguard/policy.toml.example`;
- two groups: `hkdfguard`, for the accounts that may use keys, and `hkdfguard-deployers`, for
  the accounts that write key files.

They install **no policy and no secrets**: those are decisions for each host.

```sh
hkdfguard --help
ls -l /usr/share/hkdfguard/policy.toml.example
```

## 3. Configure the TPM

### Give the service access to the TPM

The library opens `/dev/tpmrm0`, which belongs to the `tss` group on most distributions:

```sh
ls -l /dev/tpmrm0    # crw-rw---- tss tss ...
```

You'll add your application's account to `tss` in [step 7](#7-use-the-key-from-your-application).

### Create the derivation secret

Each service's KEK is derived from the TPM's own seed, the service name, and a host
**derivation secret**. Without the secret, any process that can open the TPM could derive the
same keys, so the TPM provider requires it. Create it as root, readable by the `hkdfguard`
group:

```sh
sudo sh -c '( umask 077; head -c 32 /dev/urandom > /etc/hkdfguard/tpm.derivation-secret )'
sudo chgrp hkdfguard /etc/hkdfguard/tpm.derivation-secret
sudo chmod 0440 /etc/hkdfguard/tpm.derivation-secret
```

:::danger Back up the derivation secret
The derivation secret is part of every TPM key on the host. **If it is lost or changed, every
DEK wrapped on this host becomes unrecoverable.** Copy it now to wherever you keep other
root-of-trust material, offline or in a secrets manager with tighter access than the host.

A backup protects against losing the *file*, not the *TPM*. A motherboard or TPM replacement,
or a TPM clear, changes the TPM's seed and every key derived from it.
:::

### Write the policy

Start from the example the packages install. Copied unedited, it behaves exactly like having
no policy:

```sh
sudo install -m 0644 -o root -g root /usr/share/hkdfguard/policy.toml.example \
    /etc/hkdfguard/policy.toml
```

Then edit `/etc/hkdfguard/policy.toml` to require the TPM, and to require each service to be
listed before it has a key:

```toml
[selection]
mode = "require"
provider = "tpm2"

[tpm]
require_pinned_names = true

[tpm.pinned_names]
# Filled in by step 4.
```

Why `require_pinned_names`? A TPM derives a key for *any* service name on demand, so without it
a typo in a service name silently gets its own key, and any process that can reach the TPM and
the derivation secret can use a key for a service root never provisioned. With it, a service
has a key only once root has provisioned it and added its TPM **Name** to the policy. **Set it
on every production TPM host.**

The policy must be owned by root and not writable by group or others, and so must
`/etc/hkdfguard` and every folder above it. A policy that is wrongly owned, too broadly
writable or malformed makes **every** call fail, rather than falling back to defaults. Unknown
keys are rejected, so a misspelling fails loudly. Two TOML rules catch people out:

- Top-level settings such as `security_model` and `preferred_order` must come **before** the
  first `[section]`.
- Service names under `[tpm.pinned_names]` must be **quoted**.

The library re-reads the policy on every call, so changes take effect without restarting
anything.

## 4. Provision the key

As root, once per service:

```sh
sudo hkdfguard provision --service-name com.example.myapp
```

With `require_pinned_names` set, the first run fails on purpose and prints the line to add to
the policy:

```text
error: ... add this to the policy file and run provision again:
  [tpm.pinned_names]
  "com.example.myapp" = "000b..."
```

Add the line under `[tpm.pinned_names]` exactly as printed, then run `provision` again. It now
reports the key as provisioned and verified, and prints its **fingerprint**. **Record it.**
`wrap` can be told to insist on it, and a later `provision` prints it again, so you can confirm
the key hasn't changed.

`provision` is safe to run on every deployment: it never changes an existing key, but it always
verifies it, so a missing or wrong key fails at deployment rather than at the first wrap.

## 5. Prepare a folder for key files

Under the default **production** security model, the library trusts a key file only if it,
and every folder above it up to `/`, is owned by root or a **deployer** (a member of
`hkdfguard-deployers`), and writable by nobody else. A key file anywhere under `/tmp`,
`/var/tmp` or `/dev/shm` is always refused.

Create a folder for the key files. The setgid bit keeps new files in the deployers' group, so
deployers can share it:

```sh
sudo install -d -o root -g hkdfguard-deployers -m 2775 /etc/myapp/keys
```

`wrap` can run as root, or as a dedicated deployer account. A deployer account needs:

- membership of `hkdfguard-deployers`, so its key files are trusted;
- membership of `tss` and `hkdfguard`, because wrapping uses the TPM and the derivation secret;
- membership of the service's group, to hand the key file to it with `--group`.

```sh
sudo usermod -aG hkdfguard-deployers,tss,hkdfguard,myapp deploy-agent
```

The account must sign in again to pick up the new groups.

## 6. Wrap a DEK into a key file

Run `wrap` as root, as here, or as a deployer account without `sudo`. It reads the DEK as
base64 from standard input, so the key never appears on a command line, and writes the key
file:

```sh
head -c 32 /dev/urandom | base64 -w0 | sudo hkdfguard wrap \
    --key-file-path /etc/myapp/keys/myapp.v1.key \
    --service-name com.example.myapp --dek-stdin \
    --group myapp --fingerprint 3f1c...e09a
```

- `--group myapp` gives the key file to the service's group, mode `0640`, so the service can read
  it. Without it the file is `0600`, readable only by whoever ran `wrap`. Broad groups such as
  `users`, `wheel` and `sudo` are refused.
- `--fingerprint` writes nothing unless the DEK was sealed to the key you recorded at
  `provision`.
- `--force` replaces an existing key file. The new wrap completes first, so a failed wrap never
  destroys the old file.
- `--dek-file path` reads the DEK from a file instead, such as a systemd credential:
  `--dek-file "$CREDENTIALS_DIRECTORY/dek"`.

`wrap` never creates a key. If the service isn't provisioned, it fails and names the
`provision` command.

:::warning Where the DEK comes from
This example makes a new DEK only to show the steps. In a real deployment, the DEK comes from
your release pipeline: it is the key your pipeline encrypted the application's secrets with.
A DEK can only be wrapped on the host that holds the KEK, so the pipeline delivers the
plaintext DEK to the host, wraps it there, and discards it.

Never put a DEK in an environment variable or on a command line: other processes of the same
user can read both through `/proc`. Pipe it with `printf`, a shell builtin, not an external
`echo`.
:::

## 7. Use the key from your application

HkdfGuard runs no daemon: the library loads into your application's process. Your application's
account needs the TPM (`tss`), the derivation secret (`hkdfguard`) and read access to its key file
(its own group, through `wrap --group`). Under production it is the *application*: it reads and
unwraps key files, and never writes them.

```sh
sudo usermod -aG tss,hkdfguard myapp
```

The account picks up new groups the next time it starts a session.

**With an HkdfGuard language library** (.NET, Java, Go, Node or Python), configure the service
name and the key file's full path, `/etc/myapp/keys/myapp.v1.key`. The library loads
`libhkdfguard.so.1` from the system library folder after checking it.

**Calling the C API directly**, load the library by its SONAME, `libhkdfguard.so.1`, which every
installation provides. Don't load it as `hkdfguard` or `libhkdfguard.so`: only the development
package provides that name. Then:

1. call `hkdfguard_harden_process` early, to turn off core dumps and same-user debugging;
2. call `hkdfguard_open_file` to read the key file;
3. call `hkdfguard_unwrap_dek` with the service name to recover the 32-byte DEK;
4. zero the DEK when you're done.

Do it once at startup and cache the DEK: every call opens a fresh TPM session. To build C
against the library, install `libhkdfguard-dev` (or `hkdfguard-devel`) and use
`pkg-config --cflags --libs hkdfguard`.

## Monitor it

Every key operation is recorded in the system log with the same event IDs as Windows and
macOS:

```sh
journalctl -t hkdfguard
```

On hosts without the journal, look in `/var/log/auth.log` or `/var/log/secure`.

## Other providers

**An HSM (PKCS#11).** Name the vendor's module, a root-owned PIN file and the token in the
policy. `provision` generates the key pair on the token.

```toml
[selection]
mode = "require"
provider = "pkcs11"

[pkcs11]
module = "/usr/lib/vendor/libvendor-pkcs11.so"
pin_file = "/etc/hkdfguard/pkcs11.pin"
token_label = "hkdfguard-prod"
```

**Containers (external secret).** The KEK is a P-256 private key your platform mounts, as
`dir/service-name`. The library never creates it: the mounted file is the provisioning.

```toml
[selection]
mode = "require"
provider = "external-secret"

[external_secret]
dir = "/run/secrets/hkdfguard"
require_pinned_keys = true                 # from the release after 0.9.0

[external_secret.pinned_keys]
"com.example.myapp" = "<64 hex chars>"     # the key's fingerprint
```

Mount it read-only and owner-only: `defaultMode: 0400` for a Kubernetes Secret, `perms =
"0400"` for Vault Agent. For containers, the project also publishes a `FROM scratch` overlay
image, `ghcr.io/runsecure/hkdfguard-overlay`, holding only the library and the tool.

[External secrets](../externalsecrets.md) covers creating the key with OpenSSL, delivering it, and
checking its fingerprint.

## Retire a key

`retire` deletes a service's key, permanently: nothing wrapped under it can be unwrapped
again. It takes the recorded fingerprint, and deletes nothing unless it matches:

```sh
sudo hkdfguard retire --service-name com.example.myapp --fingerprint 3f1c...e09a
```

Only **PKCS#11** keys can be retired. A TPM key isn't stored anywhere (it is re-derived on every
use), so there is nothing to delete: remove its line from `[tpm.pinned_names]` to stop it
being used, without destroying it. An external secret is removed where your platform manages
it.

## Troubleshooting

The library returns only a status code; it doesn't print reasons. The tool does, so run it
**as your application's account**, for the same service name:

```sh
sudo -u myapp hkdfguard provision --service-name com.example.myapp
```

| Status | Meaning | Fix |
|---|---|---|
| -9 | The policy can't be used: badly owned, too broadly writable, or malformed. Every call fails until it is fixed. | Run the tool to see the reason. The policy and every folder above it must be root-owned and not group- or other-writable. |
| -3 | No allowed provider is set up | Check that the account is in `tss` and that the derivation secret exists |
| -4 | A provider is present but failing | Run the tool for the exact reason: often the derivation secret's permissions |
| -17 | The service has no key | `provision` it. With `require_pinned_names`, add its pinned Name to the policy. |
| -16 | The key file was wrapped under a different key | Use the service name it was made for, or wrap it again |
| -11 | The key file was altered, or made for a different service | Restore it, or wrap it again |
| -39 | The key file, or a folder above it, is owned or writable by someone the security model doesn't trust | Move it to a folder prepared as in [step 5](#5-prepare-a-folder-for-key-files), and wrap it again as root or a deployer |
| -37 | The key file holds an *unwrapped* key | Treat it as exposed: delete the file and rotate the DEK |
| -80 | A deployer group doesn't exist or is too broad | Fix `deployer_groups` in the policy |

## Next steps

- The [hkdfguard-native-linux documentation](https://github.com/runsecure/hkdfguard-native-linux/tree/main/docs):
  - [installation](https://github.com/runsecure/hkdfguard-native-linux/blob/main/docs/installation.md),
    including the standalone tarball and the container overlay;
  - [configuration](https://github.com/runsecure/hkdfguard-native-linux/blob/main/docs/configuration.md),
    with every policy setting and TPM bus encryption for discrete TPMs;
  - [usage](https://github.com/runsecure/hkdfguard-native-linux/blob/main/docs/usage.md),
    with the full C API and status codes;
  - [troubleshooting](https://github.com/runsecure/hkdfguard-native-linux/blob/main/docs/troubleshooting.md).
- [Separation of duties](../separationofduties.md) compares development and production modes on
  every platform.
