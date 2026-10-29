---
title: Getting started with Go
sidebar_label: Go
sidebar_position: 6
description: Use HkdfGuard from Go to encrypt data and configuration secrets under a TPM- or Secure Enclave-protected key.
---

# Getting started with Go

This guide takes a Go program from nothing to encrypting and decrypting data under a key the
platform protects. It first checks the setup with an in-memory key. Then it moves to a durable
key file, encrypts configuration secrets in a deployment pipeline, and reads them back at
runtime.

`hkdfguard-go` reads and writes the same values as every other port.

## Before you start

You need:

- **Go 1.27.1 or later** for the native key wrapper module. The other modules need Go 1.25. The
  modules name Go 1.27.2 in their `toolchain` directive, so `go` downloads it on first use.
- **On macOS and Linux, cgo and a C toolchain.** The native key wrapper is built with cgo, so build
  with `CGO_ENABLED=1`. On macOS install the Xcode Command Line Tools (`xcode-select --install`);
  on Linux install `gcc`. Windows needs neither.
- **The HkdfGuard native library, installed on the machine, with a service provisioned.** Follow
  the guide for your OS first: [Windows](windows.md), [macOS](macos.md) or [Linux](linux.md).
  This guide uses the service name `com.example.myapp`.
- **An account that may use the key.** Your program must run as an account the service's key
  allows:
  - Windows: a member of `HkdfGuardUsers`.
  - Linux: in `tss` and `hkdfguard`.
  - macOS (user-scoped): the user who provisioned it.

The Go library loads the native library only from its install location, after checking its location
and ownership, its code signature (Windows and macOS), and the dynamic linker's environment. On
Linux, verify the release's attestation before installing the package: the loader checks where the
library is, not its contents. It never searches `PATH`, `LD_LIBRARY_PATH` or `DYLD_LIBRARY_PATH`.

## 1. Add the modules

HkdfGuard is three modules, so the cipher and the key wrapper can each be swapped without the
other:

| Module | What it gives you |
|---|---|
| `github.com/runsecure/hkdfguard-go` | The interfaces, plus these packages: `dek` (key rings, protectors, `dek.Options`), `encryptedconfig` and `cache` |
| `github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256` | The AES-256-GCM cipher, and the pipeline data protector |
| `github.com/runsecure/hkdfguard-go/keywrapping/nativev1` | The key wrapper over the native library (cgo on macOS and Linux) |

```sh
mkdir hkdfguarddemo && cd hkdfguarddemo
go mod init hkdfguarddemo
go get github.com/runsecure/hkdfguard-go \
    github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 \
    github.com/runsecure/hkdfguard-go/keywrapping/nativev1
```

:::note Pre-release
Go modules are released by tag. Until the modules you need are tagged, add `replace` directives
in your `go.mod` pointing at a checkout of `hkdfguard-go`: one for the root, and one each for
`cryptoprovider/aesgcm256` and `keywrapping/nativev1`.
:::

## 2. Check the setup with an in-memory key

Write `main.go`:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/runsecure/hkdfguard-go"
	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
	"github.com/runsecure/hkdfguard-go/keywrapping/nativev1"
)

func main() {
	ctx := context.Background()

	wrapper, err := nativev1.New("com.example.myapp")
	if err != nil {
		log.Fatal(err)
	}
	ring, err := dek.Build(ctx, dek.Config{
		KeyWrapper:            wrapper,
		CryptoProviderFactory: aesgcm256.NewFactory(),
		KeyRefreshInterval:    60 * time.Second,
		EphemeralKeys:         []int{1},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ring.Close()

	formats := dek.NewDefaultFormatProvider()
	aad := []byte("customer-notes") // what the value is for

	// Encrypt under the current key. Encrypt zeroes the plaintext it is given.
	version, key, err := ring.Current(ctx)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext, err := key.Encrypt(ctx, []byte("The launch code is 0000"), aad)
	if err != nil {
		log.Fatal(err)
	}
	stored, err := formats.Format(ctx, hkdfguard.KeyTrackingValue{KeyVersion: version, Value: ciphertext})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(stored)

	// Decrypt with the key for the value's own version.
	parsed, err := formats.Parse(ctx, stored)
	if err != nil {
		log.Fatal(err)
	}
	key, err = ring.Get(ctx, parsed.KeyVersion)
	if err != nil {
		log.Fatal(err)
	}
	result := make([]byte, len(parsed.Value))
	defer hkdfguard.Wipe(result)
	n, err := key.Decrypt(ctx, parsed.Value, aad, result)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", result[:n])
}
```

Run it with `go run .` on Windows, or `CGO_ENABLED=1 go run .` on macOS and Linux:

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `dek.Build` asked the native library to generate a DEK and wrap it under your service's key, then
  unwrapped it into memory that is zeroed when the ring closes. The plaintext DEK never touched
  disk.
- `ring.Current` returns the **current version** and its **data encryption key**. `Encrypt` seals
  the bytes with AES-256-GCM under that key, bound to the AAD, and zeroes the plaintext it was
  given.
- `DefaultFormatProvider.Format` turns the version and the ciphertext into the stored form,
  `enc::v1::...`: `v1` is the key version, and the rest is the ciphertext in base64. However you
  store a value, keep its version with it.
- To decrypt, `ring.Get` returns the key **for the value's own version**, not the current one, so a
  value encrypted before a rotation still decrypts. A result buffer as long as the ciphertext
  always fits the plaintext.
- The **AAD** says what the value is for. It is bound into the ciphertext, so decrypting with
  different AAD fails authentication: a value encrypted for one purpose never decrypts as another.
- `KeyRefreshInterval` re-checks the key every 60 seconds. If it stops being available, encryption
  and decryption stop after three failed checks, until access returns.
- Plaintext travels as `[]byte`, never as a `string`, so it can be zeroed: `hkdfguard.Wipe` clears
  the result buffer when you are done.

:::tip The shortcut: data protectors
`ring.CreateProtector("customer-notes")` does these same steps for text values: it takes the current
key, uses the UTF-8 of its name as the AAD, and formats the result. Values are interchangeable: a
protector named `customer-notes` decrypts the value above, and the reverse.
:::

On macOS, the first run of each freshly built binary shows a keychain prompt: choose
**Always Allow**. Sign your binary with a Developer ID, and the approval survives rebuilds. See
[the first unwrap asks for permission](macos.md#the-first-unwrap-asks-for-permission).

An **ephemeral key** lives only as long as the process, which suits short-lived data. Data you
store needs a key file.

## 3. Use a key file

In a deployment, a deployer wraps each release's DEK into a **key file** with `hkdfguard wrap`, as
the OS guides show. Your program registers it by version:

```go
ring, err := dek.Build(ctx, dek.Config{
	KeyWrapper:            wrapper,
	CryptoProviderFactory: aesgcm256.NewFactory(),
	KeyRefreshInterval:    60 * time.Second,
	KeyFiles:              map[int]string{1: "/etc/myapp/keys/myapp.v1.key"},
})
```

Use the path your OS guide prepared:

| OS | Example key file |
|---|---|
| Windows | `C:\HkdfGuardKeys\myapp\myapp.v1.key` (never under `C:\ProgramData`) |
| Linux | `/etc/myapp/keys/myapp.v1.key` |
| macOS | `~/Library/Application Support/MyApp/keys/myapp.v1.key`, or a root-owned folder in production |

The key file is read through the native library, which refuses one that another account could
have written or replaced.

**To rotate,** wrap a new DEK as `myapp.v2.key` and add it as
`KeyFiles: map[int]string{1: v1Path, 2: v2Path}`. New values use the highest version. Older
values still decrypt for as long as their key file stays registered.

**Mixing key files and ephemeral keys.** A ring can hold both. Ephemeral keys rotate (every 24
hours by default), and each rotation adds a key at the current version + 1. So give the ephemeral
key a version above every key file, or turn ephemeral rotation off. Otherwise the first rotation
would replace the key file as the current key, and values encrypted after it would be lost on a
restart. The builder refuses such a ring.

## 4. Encrypt configuration secrets in your pipeline

Your release pipeline creates the DEK and encrypts the application's secrets under it. Then, on
the target machine, it hands the same DEK to `hkdfguard wrap`. Each secret is bound to the
configuration key it is stored under, so a value moved to another key fails to decrypt:

```go
import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256"
	"github.com/runsecure/hkdfguard-go/dek"
)

func release(ctx context.Context, toolPath, keyFilePath string) error {
	// The pipeline protector generates the DEK in memory; Close zeroes it and its base64 form.
	pipeline, err := aesgcm256.NewPipelineDataProtector(dek.NewDefaultFormatProvider(), 1)
	if err != nil {
		return err
	}
	defer pipeline.Close()

	// Encrypt each secret for the configuration key it will be stored under.
	value, err := pipeline.Encrypt(ctx, []byte("Server=db;Password=s3cret"), "ConnectionStrings:Admin")
	if err != nil {
		return err
	}
	_ = value // ...write "enc::v1::..." into appsettings.json as ConnectionStrings:Admin...

	// On the target machine, wrap the same key into the release's key file.
	// Add "--group", "<the service's group>" so the application can read it.
	tool := exec.Command(toolPath, "wrap", "--service-name", "com.example.myapp",
		"--key-file-path", keyFilePath, "--dek-stdin")
	tool.Stdout, tool.Stderr = os.Stdout, os.Stderr
	stdin, err := tool.StdinPipe()
	if err != nil {
		return err
	}
	if err := tool.Start(); err != nil {
		return err
	}
	// The key crosses to the tool as bytes from the protector's own buffer, never through a string.
	_, writeErr := stdin.Write(pipeline.KeyBase64())
	closeErr := stdin.Close()
	if err := tool.Wait(); err != nil {
		return fmt.Errorf("hkdfguard wrap: %w", err)
	}
	return errors.Join(writeErr, closeErr)
}
```

`toolPath` is `C:\Program Files\HkdfGuard\v1\hkdfguard.exe` on Windows, `/usr/bin/hkdfguard` on
Linux, and `/usr/local/bin/hkdfguard` on macOS. Run this step as a deployer, as your OS guide
describes.

:::warning
Pass the DEK only on standard input, as above. Never pass it as a command-line argument or an
environment variable, and never convert `KeyBase64()` to a Go `string`: strings can't be cleared
from memory.
:::

## 5. Read the secrets back at runtime

Each configuration value is an `enc::v1::...` string, encrypted for the configuration key it is
stored under. Parse it, take the key for its version, and decrypt it with that configuration
key's AAD:

```go
encrypted := settings["ConnectionStrings:Admin"] // "enc::v1::..."
value, err := dek.NewDefaultFormatProvider().Parse(ctx, encrypted)
if err != nil {
	return err
}
key, err := ring.Get(ctx, value.KeyVersion)
if err != nil {
	return err
}
aad, err := hkdfguard.ConfigurationAAD("ConnectionStrings:Admin")
if err != nil {
	return err
}
result := make([]byte, len(value.Value))
defer hkdfguard.Wipe(result)
n, err := key.Decrypt(ctx, value.Value, aad, result)
if err != nil {
	return err
}
// use result[:n], the UTF-8 bytes of the secret
```

`hkdfguard.ConfigurationAAD` gives the AAD the pipeline bound the value to. A value copied to a
different configuration key fails authentication. The key ring must have the release's key file
registered at the version the pipeline used, here `1`.

:::tip The shortcut: `encryptedconfig`
The `encryptedconfig` package does these same steps over any configuration source, through a
lookup. `encryptedconfig.FlattenJSON` and `NewMapLookup` read an `appsettings.json`, and
`EnvLookup("APP_")` reads `A:B` from `APP_A__B`, as .NET does:
`encryptedconfig.New(ring, lookup).Decrypt(ctx, "ConnectionStrings:Admin", buffer)`.
:::

## 6. Configure the ring from appsettings.json

`dek.Options` has the field names of the .NET port's options, so one `appsettings.json` section
configures both:

```json
{
  "HkdfGuard": {
    "ServiceName": "com.example.myapp",
    "KeyRefreshInterval": 60,
    "KeyFiles": [ { "Version": 1, "Path": "/etc/myapp/keys/myapp.v1.key" } ]
  }
}
```

```go
options, err := dek.OptionsFromJSON(appsettingsJSON, "HkdfGuard")
if err != nil {
	return err
}
wrapper, err := nativev1.New(options.ServiceName)
if err != nil {
	return err
}
config, err := options.Config(wrapper, aesgcm256.NewFactory()) // validates every setting
if err != nil {
	return err
}
ring, err := dek.Build(ctx, config)
```

## 7. Harden the process

DEKs pass through your process's memory. Opt in to process hardening once, early in `main`, so
crash dumps and other processes of the same user can't read it:

```go
if err := nativev1.HardenProcess(); err != nil {
	log.Fatal(err) // don't start without it
}
```

`nativev1.HardenProcessWithOptions` takes the strict option, which fails unless no other process of
the same user can debug or inject into this one. Use it for a Windows service. Debuggers stop
working for the process.

[Process hardening](../processhardening.md) explains what each platform does, and when to
pass the flag.

## Troubleshooting

Every error wraps a sentinel you can test with `errors.Is`. A failed native call is a
`*nativev1.StatusError` (use `errors.As`), whose message includes the status code and its meaning.

| You see | Cause | Fix |
|---|---|---|
| `nativev1.ErrNotInstalled` | The native library isn't installed | Follow your OS guide's install step |
| `nativev1.ErrUntrusted` | The installed library, or a folder above it, failed verification, or a linker variable shadows it | Reinstall the native package; clear `LD_LIBRARY_PATH` and `DYLD_LIBRARY_PATH` |
| `nativev1.ErrUnsupportedPlatform` | Built with `CGO_ENABLED=0` on macOS or Linux, or an Intel Mac, or an amd64 binary under Rosetta | Build with `CGO_ENABLED=1`, for `darwin/arm64` on a Mac |
| `StatusError` -17 | No key is provisioned for this service name | Provision it, with the same service name |
| `StatusError` -18 | The key exists, but this account may not use it | Windows: add the account to `HkdfGuardUsers`. macOS: run as the user who provisioned it, in a logged-in session. |
| `StatusError` -16 or -11 | The key file was wrapped under another service's key, or altered | Use the right service name, or redeploy the key file |
| `StatusError` -39 | The key file's location isn't trusted | Move it to a folder prepared as your OS guide shows |
| `hkdfguard.ErrKeyAccessSuspended` | The key stopped answering for three refreshes in a row | Restore access to the key; operations resume on the next successful refresh |

## Next steps

- The [hkdfguard-go documentation](https://github.com/runsecure/hkdfguard-go/tree/main/docs)
  covers the `hkdfguard` tool reference, the `cache` package, diagnostics with OpenTelemetry and
  `log/slog`, and running the native integration tests.
- [Separation of duties](../separationofduties.md) explains who should run each step in
  production.
