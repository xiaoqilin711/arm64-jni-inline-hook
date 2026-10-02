/*
 * jnihook.h — minimal, dependency-free ARM64 inline hook for JNI native methods.
 *
 * This is the reusable core extracted from a real-world engagement: a hardened
 * Android app whose anti-Frida self-destruct could only be sidestepped by
 * loading a plain .so through a custom firmware's "arbitrary .so injection"
 * (no Frida agent, therefore no /memfd:frida-agent mapping to detect).
 *
 * It is NOT a general-purpose hook engine. It covers exactly one, deliberately
 * narrow case that turned out to be the highest-leverage one in practice:
 *
 *   - target is a JNI native method (AAPCS64: x0=JNIEnv*, x1=this/jclass,
 *     x2..x7 = the jvalue/jstring/jobject arguments),
 *   - its first 16 bytes (prologue) contain no PC-relative addressing, so they
 *     can be relocated verbatim into a trampoline without fixups.
 *
 * The trampoline only needs to preserve x0..x7 (the JNI calling convention
 * uses no more than x0..x7 for arguments and x8 for the indirect result) plus
 * the link register. That keeps the assembly dispatcher small and easy to audit.
 *
 * Everything target-specific (library name, offset, handler body) lives in the
 * caller. See examples/ for a complete, compilable end-to-end demo.
 */

#ifndef JNIHOOK_H
#define JNIHOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Raw hook handler signature. Arguments arrive exactly as the original JNI
 * native method received them, up to six words after `this` (x2..x7).
 *
 *   arg0 = this/jclass (x1)
 *   arg1..arg5 = the method's own arguments (x2..x6)
 *
 * Cast them to the concrete JNI types (jstring, jbyteArray, ...) inside your
 * handler — the hook layer never touches them, it only preserves and forwards.
 *
 * Return the value your handler wants the caller to see. The `orig` pointer is
 * the trampoline into the original function: call it to invoke the real
 * implementation (same signature as the handler), or skip it to short-circuit.
 *
 * NOTE: JNIEnv* is passed as a raw pointer to keep this header JNI-free and
 * unit-testable on the host; cast it back to (JNIEnv*) inside your handler.
 */
typedef void* (*jni_hook_handler_t)(void* env, void* arg0, void* arg1,
                                    void* arg2, void* arg3, void* arg4,
                                    void* arg5, void** orig);

/*
 * Install an inline hook on a JNI native method at `target`.
 *
 * Returns 0 on success; on failure returns a negative error code:
 *   -1  prologue is not position-independent (contains ADR/ADRP/B/LDR-literal),
 *       refusing to relocate it without fixups;
 *   -2  mmap of the trampoline failed;
 *   -3  mprotect(PROT_READ|PROT_WRITE|PROT_EXEC) failed.
 *
 * On success *out_orig points to a callable trampoline for the original code.
 */
int jnihook_install(void* target, jni_hook_handler_t handler, void** out_orig);

/*
 * Scan `nbytes` bytes of code starting at `code` and report whether every
 * instruction is position-independent (relocatable without fixup). Used
 * internally by jnihook_install, exposed so the check itself can be unit-tested
 * and so callers can pre-flight a candidate prologue before patching.
 *
 * Returns 1 if all bytes look position-independent, 0 if any PC-relative
 * instruction (ADR/ADRP) or literal-pool load (LDR literal) is detected.
 * NOTE: this is a conservative heuristic, not a full decoder. It flags the
 * common non-relocatable cases; a false "all clear" is possible for exotic
 * encodings, so always verify the patched target actually behaves.
 */
int jnihook_prologue_is_pic(const uint32_t* code, size_t nbytes);

#ifdef __cplusplus
}
#endif

#endif /* JNIHOOK_H */
