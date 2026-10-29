---
title: Linux key wrapper
sidebar_label: Linux
sidebar_position: 3
description: The exact cryptographic construction and payload format of HkdfGuard's Linux key wrapper, and how each provider (TPM 2.0, PKCS#11, external secret, ephemeral) holds the KEK.
---

# Linux key wrapper

`libhkdfguard.so.1` wraps a 32-byte DEK under a P-256 KEK held by one of four **providers**. It
uses the [shared construction](index.md#the-shared-wrap-construction), with RustCrypto for
SHA-256, HKDF-SHA512 and AES-256-GCM. Payloads are **132 to 276 bytes**, depending on the
provider's key identifier.

## The KEK, provider by provider

Every provider holds a P-256 key, and computes `Z = ECDH(KEK, H)` for a given point H. Where that
key lives, and where `Z` is computed, is what differs:

| Provider | Payload tag | KEK | Where `Z` is computed |
|---|---:|---|---|
| TPM 2.0 | `1` | Derived inside the TPM on every use; never stored anywhere | Inside the TPM, `TPM2_ECDH_ZGen` |
| PKCS#11 | `2` | Generated on the HSM or token, and kept there | On the token, `CKM_ECDH1_DERIVE` |
| External secret | `3` | A P-256 private key in a root-owned file the platform mounts | In process memory |
| Ephemeral | `5` | A random P-256 key in locked process memory, lost when the process exits | In process memory |

Wrapping uses the first provider that holds a key for the service, in policy order. Unwrapping
always uses the provider the payload names: the provider tag is in the payload, and
authenticated. A provider that is present but failing ends the call, rather than falling through
to a weaker one.

### TPM 2.0

The TPM provider never persists a key. It derives each service's KEK on demand with
`TPM2_CreatePrimary` under the **Owner** hierarchy. For a fixed hierarchy, template and TPM seed,
that command is deterministic: it reproduces the same key every time. This is the same mechanism
TPMs use so they never have to store a Storage Root Key. So there are no persistent handles to
manage, and no service-to-handle mapping file to protect.

The template describes a P-256 ECC key with these attributes:

- `fixedTPM`: it can never move to another TPM;
- `sensitiveDataOrigin`: the TPM generates the private key itself;
- `userWithAuth`;
- `decrypt`, and not `sign`, and unrestricted: it is usable for ECDH (`TPM2_ECDH_ZGen`) and not
  for signing.

Each service gets its own key through the template's `unique` field, which the derivation
hashes in:

```text
unique.x = SHA-256("hkdfguard-tpm2-unique-x:" || service || ":secret:" || derivation secret digest)
unique.y = SHA-256("hkdfguard-tpm2-unique-y:" || service || ":secret:" || derivation secret digest)
```

The **derivation secret** is a root-owned file, `/etc/hkdfguard/tpm.derivation-secret`. Its
digest is `SHA-256("hkdfguard-tpm2-derivation-secret-v1:" || file bytes)`, over the file's exact
bytes, with no trimming.
The digest is as sensitive as the file, and is held in a zeroizing buffer. Without it, any process that can open `/dev/tpmrm0` could issue the same
`CreatePrimary` and get the same key. An authorization value can't close that gap, because it
isn't an input to the derivation. With the secret, deriving a service's key needs the TPM *and*
the secret file.

- The secret is required by default. Without it, the `":secret:"` part is left out, and a
  warning says any process with TPM access can reproduce the keys.
- Adding, changing or losing the secret changes every TPM KEK on the host: earlier payloads then
  fail their fingerprint check (-16).
- The provider checks once per process that the secret really changes the derived key, and
  refuses to use the TPM if it doesn't.

Further TPM controls:

- **Pinned Names.** With `tpm.require_pinned_names`, only services whose TPM **Name** is listed
  in the root-owned policy have a key, and a key whose Name differs from the pin is refused. That
  makes key substitution detectable, and makes provisioning a deliberate act by root.
- **Bus encryption.** On a discrete TPM, `Z` crosses the motherboard bus.
  `tpm.session_encryption` encrypts the ECDH command's input parameter (AES-128-CFB) under a
  salted session. In `required` mode the session's salt key is pinned by its Name, so an
  attacker on the bus can't substitute it.
- **Untrusted logging.** The provider refuses to run if tpm2-tss's own `TSS2_LOG` is set to
  `debug` or `trace`, levels at which tpm2-tss logs secrets.

The payload's key identifier for the TPM provider is `SHA-256(service)`. It is a label for
diagnosis; the KEK is chosen by the service name.

### PKCS#11

`provision` generates the key pair on the token (`CKM_EC_KEY_PAIR_GEN`, P-256), labelled with the
service name. Its attributes:

- `CKA_TOKEN`, `CKA_SENSITIVE` and `CKA_DERIVE` set;
- `CKA_EXTRACTABLE`, `CKA_MODIFIABLE` and `CKA_COPYABLE` cleared;
- both halves private objects (`CKA_PRIVATE`), and only private objects are ever looked up, so
  nothing created on the token without the PIN is ever used.

ECDH runs on the token, with `CKM_ECDH1_DERIVE` and `CKD_NULL`: no token-side KDF. HkdfGuard
applies its own HKDF-SHA512 to the raw secret.

The PIN comes from a root-owned file. A PIN the token rejects stops further logins from that
process until the file changes, so a wrong PIN can't run the token's retry counter down to a
lockout. Only PKCS#11 keys can be retired.

### External secret

The KEK is a P-256 private key that the platform delivers as a file, `dir/service`: a Kubernetes
Secret, a Vault Agent sink, a systemd credential. It may be SEC1 or PKCS#8 DER (recommended, and
generated with OpenSSL), or 32 raw big-endian scalar bytes. The library never creates or writes
one. The file must be owned by root or the service's user, with no access for anyone else (or
`root:group 0440`), and every folder above it must be equally locked down, except on a read-only
mount.

File permissions limit who could have written the key, but not whether it is the key you made.
From the release after `0.9.0`, the policy can **pin** each service's key by its fingerprint,
`SHA-256(0x04 || X || Y)`, the same value every payload carries. A mounted key whose fingerprint
isn't pinned is refused, and with `require_pinned_keys` an unpinned service has no KEK at all.

This is the one non-hardware provider for persistent keys. The key is protected by the file's
permissions and its pin, and `Z` is computed in process memory.
[External secrets](../externalsecrets.md) shows how to create, fingerprint, pin and deliver one.

### Ephemeral

A random P-256 key per service, generated on first use and kept only in this process. It is used
only when a policy names it, never as a fallback.

Before creating the first one, the library hardens the process: core dumps off, and the process
non-dumpable, which also stops same-user `ptrace` and `/proc/pid/mem`. It refuses to create the
key if that fails. The scalars live in dedicated pages, excluded from core dumps and locked into
RAM where `RLIMIT_MEMLOCK` allows. Every DEK wrapped under an ephemeral key is unrecoverable after
a restart.

## Wrapping

1. **Draw** a 32-byte salt and a 12-byte nonce from the operating system's RNG.
2. **Hash the salt to a point** H, with the shared try-and-increment hash.
3. **Compute `Z = ECDH(KEK, H)`** in the provider: the TPM, the token, or process memory.
4. **Build the authenticated bytes:** every payload field except the ciphertext, in wire order,
   followed by the fingerprint (see the layout below).
5. **Derive the wrapping key** with HKDF-SHA512:
   - salt: the payload's salt;
   - IKM: Z;
   - info: `"hkdfguard-wrap-v1:" || u16le(len(service)) || service || authenticated bytes`;
   - output: 32 bytes.
6. **Seal** the DEK with AES-256-GCM, with the authenticated bytes as AAD.

`Z`, the wrapping key and every intermediate secret are held in zeroizing buffers, wiped when
they go out of scope.

## Payload layout

All integers are little-endian. `N` is the key identifier's length and `M` the ciphertext's
(always 48: the 32-byte DEK and its 16-byte tag).

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 1 | version | `1` |
| 1 | 1 | provider_type | `1` TPM2, `2` PKCS#11, `3` external secret, `5` ephemeral. `4` is unassigned and rejected. |
| 2 | 2 | key_id_len | `u16` |
| 4 | N | key_id | Provider-specific identifier, at most 144 bytes |
| 4+N | 32 | salt | Random per payload: hashed to the ECDH point, and HKDF's salt |
| 36+N | 12 | nonce | AES-GCM nonce |
| 48+N | 4 | ciphertext_len | `u32` |
| 52+N | M | ciphertext | AES-256-GCM ciphertext, tag included |
| 52+N+M | 32 | fingerprint | `SHA-256(0x04 \|\| X \|\| Y)` of the KEK's public key |

The **authenticated bytes** are every field except the ciphertext itself (version through
ciphertext_len), followed by the fingerprint. The ciphertext's declared *length* is included,
because a tamperer could otherwise shift it. One function writes the fields for both the
serialized form and the authenticated form, so they can never drift apart.

The service name is not in the payload. It is supplied on every call, and bound into the key
through HKDF's info.

## Unwrapping

Each step runs only if the one before it passed:

1. **Parse** the payload, checking every field and length. An unknown version is -12; anything
   truncated, extended or carrying a field no wrap produces is -10.
2. **Select the provider** the payload names, and load the service's KEK from it.
3. **Compare the fingerprint** with the KEK's public key. A mismatch is -16, before any ECDH.
4. **Recompute H, Z and the wrapping key.**
5. **Open with AES-256-GCM.** A tag that doesn't verify is -11.

On any failure, the caller's whole output buffer is zeroed, so no partial key material is left
behind.

## Key files

`hkdfguard_open_file` reads a payload without unwrapping it. It refuses, as -39, a file that it,
or any folder above it up to `/`, shows could have been replaced:

- owned by someone the [security model](../separationofduties.md#linux) doesn't trust;
- writable by someone else, or group-writable other than through a deployer group;
- below a sticky, world-writable folder such as `/tmp`, `/var/tmp` or `/dev/shm`. Only a
  read-only mount is exempt.

A file whose length doesn't match its own header is -35 or -36. A file that holds what looks
like an unwrapped DEK is -37, checked in constant time without decoding the contents.

## Process hardening

`hkdfguard_harden_process` turns core dumps off (hard limit included) and marks the process
non-dumpable (`PR_SET_DUMPABLE` 0). That also stops same-user `ptrace` and reads of
`/proc/pid/mem`. The `hkdfguard` tool hardens itself before reading a DEK, and locks its memory
out of swap where it can.

## Audit

Every wrap and unwrap writes a syslog record, read with `journalctl -t hkdfguard`, with the same
event IDs as Windows and macOS. Records carry the KEK fingerprint and a SHA-256 of the payload,
never key material.

## Source

The construction is in
[hkdfguard-native-linux](https://github.com/runsecure/hkdfguard-native-linux):

| File | What it holds |
|---|---|
| `src/crypto.rs` | The salt-to-point hash, HKDF, AES-GCM and the fingerprint |
| `src/payload.rs` | The payload layout |
| `src/provider/tpm2.rs`, `pkcs11.rs`, `external_secret.rs`, `ephemeral.rs` | The providers |

[docs/why-ecdh.md](https://github.com/runsecure/hkdfguard-native-linux/blob/main/docs/why-ecdh.md)
walks through the forgery attack that rules out ECIES.
