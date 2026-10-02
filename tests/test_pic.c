/*
 * test_pic.c — host-side unit tests for jnihook_prologue_is_pic().
 *
 * The hook's correctness hinges on one claim: "the first 16 bytes of the
 * target prologue contain no PC-relative instruction". This is pure bit
 * logic and can be tested off-device. Real on-device installation is covered
 * by the case study, not by this unit test.
 */

#include <stdio.h>
#include <stdint.h>

#include "jnihook.h"

static int failures = 0;

#define CHECK(cond, name) \
    do { if (!(cond)) { printf("FAIL: %s\n", name); failures++; } \
         else { printf("ok:   %s\n", name); } } while (0)

int main(void) {
    /* A benign prologue: sub sp; stp x29,x30; stp x28,x27; stp x26,x25.
     * All are add/sub or stp — no PC-relative, no literal. */
    uint32_t pic[4] = {
        0xd10083ffu, /* sub sp, sp, #0x20 */
        0xa9bf7bfdu, /* stp x29, x30, [sp, #-16]! */
        0xa9bf7bfd,  /* (dup, still an stp) */
        0xa9014ff4u  /* stp x20, x19, [sp, #16] */
    };
    CHECK(jnihook_prologue_is_pic(pic, 16) == 1, "PIC prologue passes");

    /* ADR x0, label — must be rejected. */
    uint32_t adr[4] = { 0x10000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(adr, 16) == 0, "ADR rejected");

    /* ADRP x0, page — must be rejected. */
    uint32_t adrp[4] = { 0x90000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(adrp, 16) == 0, "ADRP rejected");

    /* B #imm — must be rejected. */
    uint32_t branch[4] = { 0x14000001u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(branch, 16) == 0, "B rejected");

    /* BL #imm — must be rejected. */
    uint32_t bl[4] = { 0x94000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(bl, 16) == 0, "BL rejected");

    /* B.cond (e.g. the Go stack-check `b.ls morestack`) — must be rejected. */
    uint32_t bcond[4] = { 0x54000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(bcond, 16) == 0, "B.cond rejected");

    /* CBZ / TBZ (conditional compare-and-branch) — must be rejected. */
    uint32_t cbz[4] = { 0x34000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(cbz, 16) == 0, "CBZ rejected");
    uint32_t tbz[4] = { 0x36000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(tbz, 16) == 0, "TBZ rejected");

    /* BR xN (register branch) — must be rejected. */
    uint32_t br[4] = { 0xd61f0200u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(br, 16) == 0, "BR rejected");

    /* LDR x0, [pc, #imm] — literal pool load, must be rejected. */
    uint32_t ldrlit[4] = { 0x58000000u, 0, 0, 0 };
    CHECK(jnihook_prologue_is_pic(ldrlit, 16) == 0, "LDR-literal rejected");

    /* A benign register-offset load (not literal) must NOT be rejected. */
    uint32_t ldrreg[4] = { 0xf94003e0u, 0, 0, 0 }; /* ldr x0, [sp] */
    CHECK(jnihook_prologue_is_pic(ldrreg, 16) == 1, "LDR register-offset passes");

    /* Boundary: nbytes not a multiple of 4 — trailing bytes ignored. */
    CHECK(jnihook_prologue_is_pic(pic, 4) == 1, "single-insn slice passes");

    if (failures) {
        printf("%d test(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
