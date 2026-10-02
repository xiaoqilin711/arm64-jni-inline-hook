# Case Study: Capturing Login Traffic at the JNI Layer of a Hardened Banking App

> **Target (redacted)**: a mobile banking app (v1.0.4, package `com.xxx.xxx`). Authorized test: capture the **login request** — URL / method / headers / body / response.
> **Result**: transparently landed the login request's full business-layer parameters and response headers at the JNI entry point `resourceApi`.
> **This document is redacted for public release**: package name, API paths, channel/bank codes, tokens, journal numbers, exact timestamps, and target .so names are masked or generalized. Only the process and the reusable methodology remain.

---

## 0. The ask, and the conclusion up front

An authorized engagement, target a banking app, goal: capture the login request. The app sat on four hard problems at once:

1. **Bangbang (DexHelper) extractive packer** — the dex is extracted and encrypted; jadx only sees the loader.
2. **Active anti-Frida self-destruct** — detects frida-server and `abort()`s during constructor time.
3. **Login traffic over Go's pure crypto/tls** — never enters the system conscrypt, so eBPF can't see it.
4. **Business logic in encrypted JS bundles** — nothing plaintext to read statically.

After three conventional routes (eCapture / Frida / kernel HWBP) all hit walls, the win came from **switching the injection carrier** — a custom ROM's arbitrary-.so injection plus a self-written ARM64 fixup-free inline hook, landing the login request at the JNI entry point. This write-up covers what worked, what didn't, and the mistakes I made along the way.

---

## 1. First anomaly: the app loops back to the splash screen

Before any capture, a nastier symptom: **the app installed and launched, but every few seconds it bounced back to the initial page**, looping forever, so the login button was unreachable.

A controlled experiment pinned it down:

| Condition | App behavior |
|-----------|--------------|
| frida-server active | ~18s in, SIGSEGV crash, back to the splash loop |
| frida-server stopped | fully stable, operable |

The crash signature: `Fatal signal 11 (SIGSEGV), fault addr 0x97c`, with `pc=0x97c lr=0x0 sp=0x0` and only two `<unknown>` backtrace frames. `fault addr` and `pc` both land at a low address smaller than any valid mapping — **not a wild pointer, but control flow forcibly redirected to an unmapped low address**, the classic packer self-destruct (zero out sp/lr then `br` to a low address so the crash site is "clean" and untraceable).

> **Lesson (threaded through everything)**: *"the app runs stably" ≠ "anti-Frida is bypassed", it only means "frida-server isn't running".* I conflated the two once — pulled frida-server back up mid-test and personally destroyed the environment I'd just stabilized. **In a controlled experiment, change one variable at a time.**

---

## 2. Round one: eCapture can't see the login

Since frida was off the table, I tried eCapture (eBPF kernel-side, uprobes on the system TLS library, no process injection, no self-destruct).

`tls -m text` mode hooks only the system conscrypt `SSL_write/read`. It caught the app's **telemetry** (which uses the system stack) but never the login request.

I also hit a small trap: pinning `-p <pid>` to a process that then restarted itself mid-login, so `-p` stared at a dead PID. Switching to full capture (no PID pinning) and re-testing: the target process produced zero login plaintext — only another process's traffic (a phone vendor's connectivity probe, `GET /generate_204`).

That contrast is informative: eCapture could see a system process's conscrypt traffic and the target app's own telemetry, so **the tool itself works**; it simply couldn't see the login, which means **the login never goes through the system TLS library**.

The Go-specific `gotls` mode failed immediately with `not a Go executable` — the TLS logic lives in a **shared library** (a gomobile c-shared JNI library), not a standalone Go executable, so the Go build-info section `gotls` needs doesn't exist. **Both eCapture paths dead.**

---

## 3. A self-inflicted detour: the 32-bit / 64-bit trap

To understand the target .so, I exported it for static analysis and made a real mistake: **the first export was the 32-bit ARM build (ELFCLASS32), but the device runs arm64**, so every function offset was wrong and I burned a full analysis round on bogus addresses.

> **Lesson**: *`file` the .so before analyzing it.* 32/64-bit confusion wastes an entire round. From then on, every export was confirmed arm64-v8a.

After re-exporting 64-bit, I confirmed the login network stack is **Go pure crypto/tls** (go1.15, stack-based ABI), with `crypto/tls.(*Conn).Write` as the plaintext-write entry. The prologue starts with a Go stack check:

```asm
.text:0047F800  LDR   X1, [X28,#0x10]     ; g.stackguard0
.text:0047F804  SUB   X2, SP, #0x60
.text:0047F808  CMP   X2, X1
.text:0047F80C  B.LS  loc_47FDD4          ; stack low → morestack
.text:0047F810  STR   X30, [SP,#-0xE0]!   ; build frame
```

Note the 4th instruction, `B.LS` — a branch. That single detail is the foreshadowing for both "why HWBP can't read it" and "why a fixup-free hook must reject this kind of prologue".

---

## 4. Kernel HWBP: the Go stack-ABI dead end

With frida banned, I tried kernel hardware breakpoints (HWBP): no frida-server, no self-destruct, break on `Write` in-kernel. It hit a go1.15 stack-ABI wall:

1. **Go 1.15 uses a stack-based ABI** — arguments go on the stack, not X0–X7;
2. the kernel breakpoint handler **only saves X0–X7, only dumps memory they point to (≤128B), and never dumps the SP stack**;
3. so breaking at the `Write` entry leaves no plaintext pointer in any register.

Conclusion: **HWBP against Go stack-based plaintext is structurally awkward** — it's not about finding the right instruction, it's that no register holds the pointer at the moment of the break. Dead end.

> The inverse is worth noting: it pointed out that Frida *can* read the SP stack — which HWBP cannot — but Frida is itself locked out by anti-Frida. A loop with no exit.

---

## 5. Round two: Frida spawn early injection, locating the self-destruct

I decided to confront anti-Frida head-on with **spawn early injection** (hook before the app's main logic runs), not attach (by attach time the check has already run).

I wrote a bypass script (libc backstops on strstr/strcmp/fopen/readlink + dlopen/thread/self-destruct observers). I hit a Frida 17 API trap: `Module.findExportByName(null, ...)` — the static global-lookup form — is gone, and its crash happened *before* the suicide observer installed, so the first run observed the self-destruct but captured no backtrace. Fixing that yielded the decisive backtrace:

```
SUICIDE abort
  0x…24450  libc.so!fdopendir
  0x…43b14  libc.so!0x80b14
  0x…135d4  libDexHelper.so!0x35d4
  0x…14944  libDexHelper.so!0x4944
  0x…7b684  linker64!call_constructors+0x2c4
```

Translation: **the self-destruct is not in the business layer — it's in the Bangbang shell (libDexHelper.so) at constructor load time** — `call_constructors → shell init → sub-function → libc fdopendir directory scan → frida signature hit → abort()`.

An OBSERVE_ONLY control (print, don't tamper) still self-destructed → ruled out "our tampering broke the loader". And the observer caught the **detection's true face**: `strcmp` repeatedly hit, with the compared string being

```
/memfd:frida-agent-64.so (deleted)
```

The full chain: the shell's detection **repeatedly `fopen`/`open`s `/proc/self/maps`, strcmp's line by line, and `abort()`s on the frida-agent memfd mapping** — the smoking-gun signature Frida 17 leaves when it injects the agent via `memfd_create`. (The earlier `fdopendir` in the backtrace is a parallel detection branch.)

> I briefly considered "treat the symptom": hook read and erase lines containing frida/memfd. It turned out to be a dead end — **the shell's ELF loader also legitimately reads `/proc/self/maps` for relocation**, so blindly blocking/rewriting breaks the loader. This is a direct reason for the route(c) pivot below.

---

## 6. Another thread: the login logic isn't in the Java dex

In parallel, I chased where the login logic actually lives. Full dump + extractive dump, then jadx: **only packer-loader classes, no business classes**. Runtime files and APK assets are all high-entropy encrypted `.dat` (no gzip magic, no `PK`, no plaintext JS).

Conclusion: a **MADP/Weex framework app**, with the login page as an encrypted JS bundle decrypted at runtime and fed to the Weex JS engine. **Static plaintext is a total dead end**; the login logic only exists in memory at runtime.

---

## 7. The pivot: native-registration monitoring → the choke point

With all three conventional routes broken, I turned to the custom ROM's built-in capabilities. There's also a methodological brake: **stop after three consecutive failed dynamic tests on the same detection chain** and go static — the Frida route had already burned several.

Using the ROM's **native function registration monitoring** (logcat `RegisterNative`), I captured one cold start. Among thousands of registrations, the only two non-system .so files were the Weex renderer and the business core. The business core contained the decisive methods:

```
funcName: byte[] worker.ApiResponse.getBody()        @offset=…
funcName: java.lang.String worker.ApiResponse.getCode()
funcName: worker.ServiceWorker.resourceApi(String,String,String,String,boolean) → worker.ApiResponse
funcName: worker.Worker.aesEncrypt(String) → String
```

**This is the breakthrough**: the business core isn't just a TLS library — it's a complete **ServiceWorker engine** written in Go (the `go.Seq`/`go.Universe` in the signatures are gomobile-bind fingerprints). `resourceApi` is the **single choke point for all network requests** (4 Strings + 1 bool, returns `ApiResponse`); every API — including login — passes through it, and `ApiResponse.getBody/getCode/getHeader` are the plaintext response outlets.

That's a full layer *above* hooking `crypto/tls Write`: **no Go stack-ABI TLS internals to touch — read the business layer's raw url/method/body/header directly at the JNI boundary**.

The address math also closed the loop (`base + offset == the funcAddr in the log`), proving the offset is the IDA file offset.

---

## 8. The final step: switch the carrier + write the inline hook

The custom ROM only provides "let the app load an arbitrary .so" — **no off-the-shelf hook framework** — so I wrote my own. It's the ARM64 fixup-free inline hook in this repo ([src/jnihook.c](../src/jnihook.c)).

**Why this survives**: the detection keys on "a frida-agent mapped into the process via memfd". Switch to "the ROM `dlopen`s an ordinary .so" — **no frida-agent, no memfd mapping** — and the maps scan never fires, with no frida-server anywhere. The single most important insight of the whole engagement:

> **Detection and capture are orthogonal problems. Anti-Frida self-destruct targets the frida-agent memfd signature, so use an injection method that produces no such signature, and the self-destruct simply never triggers.**

Key implementation points (detailed in the library comments):

1. **Argument semantics pinned down**: the order of `resourceApi`'s 4 Strings (url/method/body/header) was confirmed twice — statically (the Go implementation's debug log concatenation `"Receive :url:"+a2+",method:"+a3…` hardcodes the order) and dynamically (post-injection prints matched real traffic 100%).
2. **Fixup-free trampoline**: confirm the prologue's first 16 bytes have no PC-relative instruction (exactly what `jnihook_prologue_is_pic` does), then copy them verbatim.
3. **Prologue-patching inline hook, not RegisterNatives-table swapping**: the latter needs `FindClass("worker/ServiceWorker")` to re-acquire the class, but that class is held by the system classloader and invisible to the injected .so's native thread — the classic classloader block. Inline hook needs no FindClass; X0 is already `JNIEnv*`.

**Verification** via three logcat lines (values redacted):

```
libcdbhook loaded, pid=<redacted>
libtarget base=0x… target=0x…
inline hook resourceApi ret=0 orig=0x…
```

The critical third line: after changing 16 bytes of `.text`, **the app kept running with no second self-destruct** → the target .so has no `.text` CRC self-check (the standing risk, resolved empirically).

---

## 9. Result: the login request, landed

After injecting, a human completes the login. `resourceApi` fires, plaintext lands. Filtering the login request out of the traffic (fields redacted):

```http
POST /pweb/app***.do HTTP/1.1
Host: 127.0.0.1:<redacted>        # local weex proxy
Accept: application/json
stage-type: weex
X-AuthToken: <redacted>
user-agent: Pixel 6(Android/15) (com.xxx.xxx/1.0.4) Weex/0.28.0.1
Content-Length: <redacted>

{"loginId":"<3-segment | separated ciphertext>","loginIdType":"C","loginType":"R",
 "password":"<base64, prefix MDAw…>","_macAddr":"<redacted>",
 "token":"<redacted>","sid":"<redacted>","verifyToken":"<redacted>",
 "_terminalType":"ANDROID","_channelId":"PM**","_bankId":"1***",
 "_deviceId":"<redacted>","_accessNo":"<redacted>"}
```

Response:

```http
HTTP/1.1 200
Server: nginx
Content-Type: application/json
Content-Length: 138
Set-Cookie: X-LB=<redacted>; HttpOnly
_traceid: <redacted>
```

Notable points:

- **Host is a local loopback proxy**: the app routes resources and APIs through a local weex proxy that forwards to the real backend (`Server: nginx` on the response confirms an nginx backend).
- **`loginId` is a 3-segment `|`-separated ciphertext, `password` is base64**: at this JNI boundary the credentials are *already* ciphertext — the plaintext was encrypted one layer up in the Weex/JS layer. Recovering the encryption means reversing `Worker.aesEncrypt`; that's a separate task.

---

## 10. Honest boundaries (what this didn't do)

1. **Response body plaintext missing**: the hook's `dump_response` writes `getBody()` bytes only in the file branch; the logcat branch logs just the length. This run pulled logcat, so the 138-byte body wasn't landed. Change the hook to `LOGI` the body (or ensure the file is read) and re-login once.
2. **Not on-the-wire bytes**: the hook captures JNI business-layer arguments, not real HTTP bytes. Headers Go `net/http` appends when sending (`Connection`, `Accept-Encoding`, real `Cookie: SESSION=…`) aren't visible at this layer.
3. **Encryption not reversed**: the `loginId`/`password` encryption (`aesEncrypt`) wasn't reversed. The captured login request is replayable as-is, but it's not plaintext credentials.
4. **Anti-Frida sidestepped, not eliminated**: route(c) succeeds by *avoiding* the memfd detection, not by killing it. The shell's OLLVM self-destruct logic is still there — it just never fires.

---

## 11. Retrospective: the trade-offs

Three real turning points:

1. **eCapture sees nothing → login is Go crypto/tls, not the system library** — eliminated the laziest option;
2. **Frida spawn backtrace → self-destruct is in the shell constructor, keyed on the memfd signature** — told us *what* detection was looking for;
3. **native-registration monitoring → `resourceApi` is the network choke point** — raised the capture from "claw plaintext out of the TLS bottom" to "read arguments at the JNI boundary", far cleaner.

The thread running through all of it: **detection and capture are orthogonal**. Often **switching the injection carrier is cheaper than fighting the detection code**.

For anyone hitting the same shape: financial apps are layered (shell self-destruct, Go stack ABI, encrypted JS bundles, business-layer encryption). Don't expect one path to carry you through. **Each dead end tells you where to look next** — eCapture's dead end points at Go tls, HWBP's at the stack ABI, Frida's at the memfd detection, static JS at the runtime entry point. Chain the dead ends together and the path opens up.

---

## Appendix: reusable vs. one-off

| Kind | Content | Where |
|------|---------|-------|
| **Reusable** | ARM64 fixup-free inline hook framework, PIC preflight, trampoline/patch layout | this repo, [src/](..) |
| **Reusable methodology** | "switch the carrier to dodge memfd detection", native-registration monitoring to find the choke point, Go stack-ABI awareness | §5–§8 above |
| **One-off (not open-sourced)** | the target APK, packer IDA exports, real login capture, Frida bypass scripts | not in this repo |
