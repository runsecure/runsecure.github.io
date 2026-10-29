---
title: Process hardening
sidebar_position: 4
description: What HkdfGuard's process hardening does on Windows, macOS and Linux, and the flag each language's Apply method takes to make it strict.
---

# Process hardening

An unwrapped data encryption key (DEK) lives in your application's memory while it is in use. A
crash dump, or another process of the same user that attaches a debugger or reads that memory,
could recover it. Process hardening closes those routes.

It is **opt-in**. The native library never does it by itself, because it changes process-wide
state your application owns: debuggers, crash reporters and dump tools stop working for the
process. Call it **once, early in startup**, before your application handles any key material.
It is the same call in every language, and on every platform it is backed by the native library's
`hkdfguard_harden_process_with_flags`.

## The call and its flag

There is one flag, the same bit on every platform: **require protected signature**. Without it you
get the *plain* hardening: everything the process can do for itself, with a weak spot only logged.
With it, the call **fails** unless no other process of the same user can attach a debugger to, or
inject code into, this one.

| Language | Plain | With the flag |
|---|---|---|
| .NET | `NativeProcessHardening.Apply()` | `NativeProcessHardening.Apply(ProcessHardeningOptions.RequireProtectedSignature)` |
| Java | `NativeProcessHardening.apply()` | `NativeProcessHardening.apply(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE)` |
| Go | `nativev1.HardenProcess()` | `nativev1.HardenProcessWithOptions(nativev1.RequireProtectedSignature)` |
| Node.js | `hardenProcess()` | `hardenProcess({ requireProtectedSignature: true })` |
| Python | `NativeProcessHardening.apply()` | `NativeProcessHardening.apply(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE)` |
| C | `hkdfguard_harden_process()` | `hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE)` (`0x1`) |

The language names are listed in each library's own options type: `ProcessHardeningOptions` in
.NET and Python, `ProcessHardeningOption` in Java, `HardenProcessOptions` in Go, and
`ProcessHardeningOptions` in Node.js. Each library loads and verifies the native library first, if
it isn't loaded yet.

What the flag does depends on the platform:

| Platform | Plain hardening | What the flag adds |
|---|---|---|
| [Windows](#windows) | Heap left out of crash reports; the process and its current threads closed to every account but SYSTEM | Also closes threads, child processes and named objects created **later**. Fails if that can't be done. |
| [macOS](#macos) | Core dumps off; debugger attachment denied; the host's code signature checked, and a weak one logged | Makes a weak code signature a **failure** instead of a warning |
| [Linux](#linux) | Core dumps off; the process made non-dumpable, which also blocks same-user `ptrace` | Nothing: the plain call already guarantees it. Accepted, so the same call works everywhere. |

## Rules on every platform

- **Call it once, early.** First thing at startup, before your application reads a key file or
  builds a key ring. Calling it again is safe: it is idempotent.
- **Treat a failure as a reason not to start.** Every library throws or returns an error if
  hardening fails. Steps applied before a failure stay applied: there is no rollback.
- **Unknown flags are refused before anything changes.** Each library rejects an option it
  doesn't define before it calls the native library, and the native library rejects an unknown bit
  with `HKDFGUARD_ERR_INVALID_ARGUMENT` (-1). A newer flag is never silently ignored by an older
  library.
- **It is a same-user barrier.** It stops other processes running as *your application's
  account*. It does not stop administrators, root, SYSTEM, `SeDebugPrivilege`, `CAP_SYS_PTRACE` or
  the kernel. It does not keep memory out of swap, the page file or hibernation files.

## Windows

### Plain hardening

1. **Windows Error Reporting leaves the heap out** of any crash report it collects for the process
   (`WerSetFlags` with `WER_FAULT_REPORTING_FLAG_NOHEAP`).
2. **The process's access list is replaced.** Only SYSTEM may read or write its memory, inject
   threads, duplicate its handles or change its security. The account it runs as keeps only query,
   synchronize and terminate access: tools can still list it, wait on it and stop it, but can't dump
   it (Task Manager's "Create dump file", procdump, `MiniDumpWriteDump`) or attach a debugger.
3. **Every thread that exists at the time is closed the same way**, so its registers can't be read
   and its execution can't be redirected.

The gap is **threads created after the call**. They get the default thread access list, so
another process of the same user can suspend them and read or change their registers. The
process's memory stays closed.

### With the flag

It adds two steps, applied first:

4. **The process token's default access list is replaced.** Every unnamed object the process
   creates from then on receives it, threads included. SYSTEM keeps every right; the account keeps
   only `SYNCHRONIZE` and `READ_CONTROL`. Later threads are then as closed as existing ones.
5. **The token's own access list is replaced**, so the account may only query and duplicate it.
   Otherwise a same-user process could open the token and put the old default back. Duplicate is
   kept because the TPM key store duplicates its own token on every key open.

**The cost is why it's a flag.** Everything the process creates afterwards without its own
security descriptor is closed to its own account too:

- a child process can't be stopped from Task Manager (its creator's handle still works);
- a same-user client can't connect to a named pipe the process created with a default security
  descriptor;
- the same goes for named events and other named objects.

**Use the flag for a Windows service or console application.** Every language runtime starts
threads you don't control, before `main` runs or whenever it needs them:

- the .NET runtime's finalizer, thread pool, timers and `async` I/O workers;
- the JVM's garbage collector, JIT compiler threads, `ForkJoinPool` and virtual-thread carriers;
- the Go runtime's threads for blocking system calls and cgo calls;
- Node.js's libuv thread pool, which runs HkdfGuard's own native calls;
- Python's thread pools, asyncio's default executor, and any library's background thread.

The plain call can only close the threads that exist when it runs. Avoid the flag only if your
process shares named pipes or other named objects with other processes of the same account.

**Limits.**

- A GUI process can still have code injected through window hooks (`SetWindowsHookEx`) by a
  same-user process on the same desktop. Keep key handling in a process without windows.
- Handles to the process or its threads opened *before* the call keep the access they were opened
  with.
- Machine-wide dump settings (WER `LocalDumps`, kernel dumps) are an administrator's to manage.

## macOS

### Plain hardening

1. **Core dumps off:** `RLIMIT_CORE` set to 0, soft and hard limits.
2. **Debugger attachment denied:** `ptrace(PT_DENY_ATTACH)`, so later debugger attaches fail. If a
   debugger is *already* attached, for example under Xcode's debugger, the call fails with
   `HKDFGUARD_ERR_PROCESS_HARDENING_FAILED` (-20) instead, because the kernel would otherwise
   terminate the process.
3. **The host executable's code signature is checked.** On macOS, what really stops another
   process of the same user from reading this one's memory, through its task port, is the code
   signature of the *main executable*:
   - signed with the **Hardened Runtime** (`codesign --options runtime`);
   - without the `com.apple.security.get-task-allow` entitlement, which Xcode adds to Debug builds;
   - without the entitlements that allow `DYLD_*` environment variables or unsigned libraries.

   The library can check that signature, but can't change it. A weak signature is only **logged**
   (unified log, subsystem `com.hkdfguard`, category `hardening`), and the call still succeeds.

### With the flag

A weak signature becomes a **failure** (-20) instead of a warning. Steps 1 and 2 are applied even
when it fails.

**Use the flag only in a signed release build** of your own executable or app bundle. It fails for
any host you didn't sign with the Hardened Runtime:

- the stock interpreters and launchers: `dotnet`, `node`, `python3`, and a `java` launcher whose
  entitlements allow debugging or `DYLD_*`;
- `go run`, `go test` and a plain `go build`, which are unsigned or ad-hoc signed;
- Xcode Debug builds.

A common pattern is the plain call in development and the flag in release:

```c
#if DEBUG
int status = hkdfguard_harden_process();
#else
int status = hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE);
#endif
```

To check what a host's signature allows: `codesign -d --entitlements - path/to/executable`.

## Linux

### Plain hardening

1. **Core dumps off:** `RLIMIT_CORE` set to 0, soft and hard limits.
2. **The process is made non-dumpable:** `prctl(PR_SET_DUMPABLE, 0)`. This also stops other
   non-root processes of the same user from attaching with `ptrace` or reading `/proc/pid/mem`.

**Call it after any privilege change.** The kernel resets the dumpable flag when a process's
credentials change, for example after it drops from root to a service account. Harden after the
drop.

The library also applies this hardening by itself before it creates an **ephemeral** KEK, whose
only protection is the process's memory, and refuses to create one if hardening fails.

### With the flag

It is accepted and adds nothing: on Linux the plain call already guarantees that no same-user
process can debug or inject into this one, whatever the binary. So a cross-platform application can
pass the flag on Linux and Windows alike.

## Choosing per platform

| Platform | Recommended |
|---|---|
| Windows | **The flag**, for any service or console application. The plain call only if the process shares named objects with other processes of its account. |
| macOS | **The plain call** for development and unsigned hosts. **The flag** in a release build signed with the Hardened Runtime. |
| Linux | Either. The flag changes nothing, so pass it if it keeps your code uniform. |

For example, in Node.js:

```ts
import { hardenProcess } from '@runsecure/hkdfguard-keywrapping-native-v1';

// Strict where the platform can guarantee it for this host; plain on macOS, where an unsigned node can't.
hardenProcess({ requireProtectedSignature: process.platform !== 'darwin' });
```

## When it fails

Each library reports a failure in its own way. All of them mean: don't start.

| Language | Hardening failed, or the host can't meet the flag | An option the library doesn't define |
|---|---|---|
| .NET | `InvalidOperationException` | `ArgumentOutOfRangeException` |
| Java | `IllegalStateException` | (the options are an enum: none can be undefined) |
| Go | `*nativev1.StatusError` | an error, before any native call |
| Node.js | `StatusError` | `InvalidArgumentError` |
| Python | `RuntimeError` | `ValueError` |
| C | `HKDFGUARD_ERR_PROCESS_HARDENING_FAILED` (-20) | `HKDFGUARD_ERR_INVALID_ARGUMENT` (-1) |

The native library can also fail to load first, with the same errors as any other HkdfGuard call:
not installed, untrusted, or an unsupported platform. See each
[getting-started guide](gettingstarted/index.md) for those.
