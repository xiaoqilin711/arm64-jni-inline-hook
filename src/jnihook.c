/*
 * jnihook.c — implementation of the minimal ARM64 JNI inline hook.
 *
 * Control flow
 * ------------
 *   caller -> [target prologue patched]  ->  dispatch_call  (normal C fn)
 *                                                |
 *                                                +-> handler (user code)
 *                                                |      |
 *                                                |      +-> orig() = trampoline
 *                                                |               -> original prologue
 *                                                |               -> original body  (runs exactly once)
 *                                                |               -> returns to handler
 *                                                |
 *                                                +-> handler's return value -> caller
 *
 * Patch layout (16 bytes written over the target's prologue):
 *
 *     ldr  x16, #8      ; 0x58000050   load the 64-bit literal at PC+8
 *     br   x16          ; 0xd61f0200   branch to dispatch_call
 *     .quad dispatch_call
 *
 * dispatch_call is an ordinary C function: the compiler generates an
 * AAPCS64-compliant prologue/epilogue, so all callee-saved registers and the
 * return address (x30) are preserved for us. We deliberately do NOT hand-write
 * any naked assembly — that is where subtle double-execution / register-clobber
 * bugs come from. Because `br` does not touch x30, dispatch_call's prologue
 * saves the original caller's return address and its epilogue returns to it.
 *
 * Trampoline layout (32 bytes, RWX mmap), invoked by the handler as orig():
 *
 *     [16 bytes copied verbatim from target]
 *     ldr  x16, #8      ; 0x58000050
 *     br   x16          ; 0xd61f0200
 *     .quad target+16   ; continue the original function after the prologue
 */

#include <stdint.h>
#include <string.h>

#include "jnihook.h"

/* The prologue position-independence check is pure bit logic and is compiled
 * everywhere (so it can be unit-tested on any host). The install path needs
 * mmap/mprotect and only makes sense for ARM64 Android, so it is compiled out
 * on hosts that lack POSIX memory-management (notably native Windows). */

/* ------------------------------------------------------------------ */
/* Prologue position-independence check                                */
/*                                                                     */
/* Three instruction classes are NOT position-independent and therefore */
/* cannot be relocated verbatim into a trampoline:                     */
/*                                                                     */
/*   1. Any branch — in AArch64, bit 26 is set for the ENTIRE branch    */
/*      category (B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR, BLR, RET, and  */
/*      the system instructions). This is a hardware-level invariant,   */
/*      not a heuristic: every instruction with bit 26 set encodes a    */
/*      control-flow transfer whose target is an address.              */
/*                                                                     */
/*   2. ADR / ADRP — "form PC-relative address". Top byte 0x10 / 0x90.  */
/*                                                                     */
/*   3. LDR/LDRSW/PRFM (literal) — load from the literal pool. These    */
/*      share bits [28:26] == 110 (a pattern no data-processing or      */
/*      register-offset load/store uses).                              */
/* ------------------------------------------------------------------ */

int jnihook_prologue_is_pic(const uint32_t* code, size_t nbytes) {
    size_t ninstr = nbytes / 4;
    size_t i;
    for (i = 0; i < ninstr; i++) {
        uint32_t insn = code[i];

        /* 1. any branch (bit 26 set) */
        if (insn & 0x04000000u) return 0;

        /* 2. ADR / ADRP (PC-relative address) */
        if ((insn & 0x9f000000u) == 0x10000000u) return 0; /* ADR  */
        if ((insn & 0x9f000000u) == 0x90000000u) return 0; /* ADRP */

        /* 3. literal-pool load (bits [28:26] == 110) */
        if ((insn & 0x1c000000u) == 0x18000000u) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Dispatcher (ordinary C function — patched target branches here)     */
/* ------------------------------------------------------------------ */

/* Set by jnihook_install before any dispatch occurs. */
static void* volatile g_orig_trampoline = 0;
static jni_hook_handler_t g_handler = 0;

/*
 * Signature deliberately matches the JNI native calling convention so the
 * arguments arrive in the correct registers (x0=env, x1=this, x2..x6 = the
 * method's own arguments) with no copying:
 *
 *   env = JNIEnv* (x0)
 *   a0  = this/jclass (x1)
 *   a1..a5 = method arguments (x2..x6)
 *
 * `noinline` + external linkage guarantee a real call target the patch can
 * branch to; the compiler may not fold or eliminate it.
 */
__attribute__((noinline))
void* jnihook_dispatch(void* env, void* a0, void* a1, void* a2,
                       void* a3, void* a4, void* a5) {
    void* orig = g_orig_trampoline;
    return g_handler(env, a0, a1, a2, a3, a4, a5, &orig);
}

/* ------------------------------------------------------------------ */
/* Installation (ARM64 Android only — needs mmap/mprotect)             */
/* ------------------------------------------------------------------ */

#if !defined(_WIN32)

#include <unistd.h>
#include <sys/mman.h>

int jnihook_install(void* target, jni_hook_handler_t handler, void** out_orig) {
    uint8_t* tramp;
    uint32_t ldr = 0x58000050u; /* ldr x16, #8 */
    uint32_t br  = 0xd61f0200u; /* br  x16     */
    uint64_t ret;
    uint64_t rep;
    uint8_t patch[16];
    long ps;
    uintptr_t pg;

    if (!target || !handler || !out_orig) return -1;

    /* 1. Refuse to relocate a non-PIC prologue (would need fixups). */
    if (!jnihook_prologue_is_pic((const uint32_t*)target, 16)) return -1;

    /* 2. Trampoline: 16 bytes of original prologue + jump back. */
    tramp = (uint8_t*)mmap(NULL, 32, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return -2;
    memcpy(tramp, target, 16);
    ret = (uint64_t)((uintptr_t)target + 16);
    memcpy(tramp + 16, &ldr, 4);
    memcpy(tramp + 20, &br, 4);
    memcpy(tramp + 24, &ret, 8);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 32);

    /* 3. Publish state so the dispatcher can reach handler + trampoline. */
    g_handler = handler;
    g_orig_trampoline = tramp;

    /* 4. Patch target: ldr x16,#8; br x16; .quad jnihook_dispatch. */
    rep = (uint64_t)(uintptr_t)&jnihook_dispatch;
    memcpy(patch + 0, &ldr, 4);
    memcpy(patch + 4, &br, 4);
    memcpy(patch + 8, &rep, 8);

    ps = sysconf(_SC_PAGESIZE);
    pg = (uintptr_t)target & ~(ps - 1);
    /* Protect two pages: the 16-byte patch may straddle a page boundary. */
    if (mprotect((void*)pg, (size_t)ps * 2,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        munmap(tramp, 32);
        return -3;
    }
    memcpy(target, patch, 16);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    mprotect((void*)pg, (size_t)ps * 2, PROT_READ | PROT_EXEC);

    *out_orig = tramp;
    return 0;
}

#else  /* _WIN32: no POSIX mmap/mprotect — install is not supported here */

int jnihook_install(void* target, jni_hook_handler_t handler, void** out_orig) {
    (void)target; (void)handler; (void)out_orig;
    return -3; /* unsupported on this host */
}

#endif /* !_WIN32 */
