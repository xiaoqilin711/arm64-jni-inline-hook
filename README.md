# arm64-jni-inline-hook

A **minimal, dependency-free ARM64 JNI fixup-free inline hook**. It transparently dumps the arguments and return value of a JNI native method in a hardened Android app — without running frida-server or injecting a frida-agent, so anti-Frida self-destructs that scan `/proc/self/maps` for `/memfd:frida-agent` never fire.

---

## Positioning

> Not another general-purpose "hook engine". It solves exactly one real, high-leverage case: when the target is a **JNI native method** whose prologue's first 16 bytes contain **no PC-relative addressing**, redirect it to your handler through a 32-byte fixup-free trampoline, then read the plaintext arguments with `GetStringUTFChars` inside the handler.

## Why this exists

The failure modes of the usual approaches are the reason this code exists:

| Approach | Problem |
|----------|---------|
| Frida (spawn/attach) | The agent maps into the process via memfd, leaving `/memfd:frida-agent-64.so (deleted)` in `/proc/self/maps`; the packer's maps scanner hits it and calls `abort()` |
| eCapture / eBPF uprobe | Only hooks the system libssl/conscrypt; the target's login traffic uses **Go's pure crypto/tls** and never enters the system TLS library |
| Kernel HWBP | Go 1.15 stack-based ABI: the plaintext slice pointer lives on the **stack**, so no register holds it at the breakpoint |

The one path that survives: **switch the injection carrier** — use a custom ROM's "arbitrary .so injection" to have the target process `dlopen` an ordinary .so you wrote (no memfd mapping), and install the inline hook from that .so's constructor.

## Features

- **Fixup-free trampoline**: if the prologue's first 16 bytes contain no PC-relative instruction, they are copied verbatim — no relocation needed.
- **Verifiable PIC preflight**: `jnihook_prologue_is_pic()` rejects non-relocatable prologues before patching, using hardware-level AArch64 invariants (bit 26 = every branch; `ADR/ADRP`; `LDR-literal` has `bits[28:26] == 110`).
- **Zero dependencies**: links only against `log`; no Dobby/Substrate or any other hook framework.
- **Plain-C dispatcher**: no hand-written naked assembly; register preservation is guaranteed by the compiler's ABI.
- **Unit-tested pure logic**: the PIC preflight is pure bit logic and ships with host-side unit tests.

## Quick start

### 1. Cross-compile

```bash
NDK=/path/to/android-ndk ./build.sh        # produces build/libjnihook.so
```

or manually:

```bash
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android24-clang \
    -shared -fPIC -O2 -Iinclude src/jnihook.c -o libjnihook.so -llog
```

### 2. Write your handler

See [examples/resource_api_dump.c](examples/resource_api_dump.c). The three essential steps:

```c
#include "jnihook.h"

static void* on_api(void* env, void* thiz, void* a1, void* a2,
                    void* a3, void* a4, void* a5, void** orig) {
    JNIEnv* e = (JNIEnv*)env;
    jstring url = (jstring)a1;                 /* args land in JNI register order */
    const char* s = (*e)->GetStringUTFChars(e, url, NULL);
    /* ... persist s ... */
    return *orig;                              /* or call the original, return its result */
}

/* from a constructor, after polling for the target library's base address: */
jnihook_install((void*)(base + TARGET_OFF), on_api, &orig);
```

### 3. Inject into the target process

Use your ROM's "arbitrary .so injection" path (**not** Frida). Put the compiled .so into the loader directory; the app `dlopen`s it on next launch and the constructor installs the hook.

## Architecture

```
original call
  │
  ├─ target(0xXXXX)  ── patch ──▶  ldr x16,#8; br x16; .quad jnihook_dispatch
  │                                        │
  │                                        ▼
  │                            jnihook_dispatch (ordinary C function)
  │                                        │
  │                              ┌─────────┴─────────┐
  │                              │                   │
  │                        your handler ──▶ orig() = trampoline
  │                              │             └─ original prologue (16B)
  │                              │                └─ original body (runs exactly once)
  │                              │
  │                              └── handler return value ──▶ original caller
```

- **Trampoline**: `[16 original bytes] + ldr x16,#8 + br x16 + .quad target+16` (32B, RWX mmap).
- **Patch**: `ldr x16,#8 + br x16 + .quad jnihook_dispatch` (16B, overwrites the prologue).
- **`jnihook_dispatch`** is an ordinary C function; the compiler emits an ABI-compliant prologue/epilogue that saves/restores callee-saved registers and the return address.

## Honest boundaries

Nothing here claims an unverified capability. Specifically:

1. **ARM64 only.** 32-bit ARM / x86 are not implemented or tested.
2. **JNI methods with ≤5 integer/pointer arguments only** (`this` + x2..x6). The 6th argument (x7) and floating-point arguments (d0-d7) are neither saved nor forwarded.
3. **The prologue must be PIC.** Functions containing `ADR/ADRP/B/BL/B.cond/CBZ/TBZ/BR/LDR-literal` are rejected (return `-1`).
4. **No `.text` CRC countermeasures.** If the target .so self-verifies its `.text` integrity, changing 16 bytes may trigger a second self-destruct. This framework only guarantees "the injection leaves no frida-agent memfd mapping", not that all integrity checks are bypassed.
5. **Unit tests not yet executed on-device**: `tests/test_pic.c` cross-compiles to an arm64 executable, but the authoring environment had no host compiler and no connected device, so the PIC invariants were verified by per-instruction disassembly + cross-compilation, not execution. Push the binary and run `adb shell /data/local/tmp/test_pic`.
6. The capture point is the **JNI business-layer arguments**, not on-the-wire bytes; low-level headers appended by Go `net/http` are not visible at this layer.

## Case study

The full write-up — what worked and what dead-ended — is in [docs/case-study.md](docs/case-study.md): an authorized engagement to capture a hardened app's login request, from the eCapture / Frida / HWBP dead ends to the JNI business-layer entry point this framework lands on.

## License

[MIT](LICENSE)
