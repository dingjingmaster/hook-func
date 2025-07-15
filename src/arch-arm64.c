//
// Created by dingjing on 25-6-16.
//

#include "arch-arm64.h"

#ifdef ARCH_ARM64

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "log.h"
#include "disasm.h"
#include "hook-func.h"
#include "hook-func-internal.h"

#undef PAGE_SIZE
#define PAGE_SIZE                           4096

// imm26 at bit 25~0
#define IMM26_MASK                          0x03FFFFFF
#define IMM26_OFFSET(ins)                   ((int64_t)(int32_t)((ins) << 6) >> 4)

// imm19 at bit 23~5
#define IMM19_MASK                          0x00FFFFE0
#define IMM19_OFFSET(ins)                   (((int64_t)(int32_t)((ins) << 8) >> 11) & ~0x3l)
#define IMM19_RESET(ins)                    ((ins) & ~IMM19_MASK)
#define TO_IMM19(imm19)                     ((imm19) << 5)

// immhi at bit 23-5 and immlo at bit 30~29, used by ADR and ADRP
#define IMM_ADR_OFFSET(ins)                 (IMM19_OFFSET(ins) | (((ins) >> 29) & 0x3))

// imm14 at bit 18~5
#define IMM14_MASK                          0x0007FFE0
#define IMM14_OFFSET(ins)                   (((int64_t)(int32_t)((ins) << 13) >> 16) & ~0x3l)
#define IMM14_RESET(ins)                    ((ins) & ~IMM14_MASK)
#define TO_IMM14(imm14)                     ((imm14) << 5)

// Rd and Rt at bit 4~0
#define RD_MASK                             0x0000001F
#define RD_REGNO(ins)                       ((ins) & RD_MASK)
#define RT_REGNO(ins)                       ((ins) & RD_MASK)

// Rn at bit 9~5
#define RN_MASK                             0x000003E0
#define RN_REGNO(ins)                       (((ins) & RN_MASK) >> 5)
#define TO_RN(regno)                        ((regno) << 5)

#define RESET_AT(ins, pos)                  ((ins) & ~(1u << (pos)))
#define INVERT_AT(ins, pos)                 (((ins) & (1u << (pos))) ^ (1u << (pos)))

typedef struct _MakeTrampolineContext       MakeTrampolineContext;

struct _MakeTrampolineContext
{
    HookFunc*               hookFunc;
    IpDisplacement*         ripDisp;
    const Insn*             src;
    const Insn*             dstBase;
    Insn*                   dst;
};

static int to_reg_no(HookFunc* funcHook, uint32_t availRegs, uint32_t* regNo)
{
    if (availRegs & HOOK_FUNC_ARM64_REG_X9) {
        *regNo = 9;
    }
    else if (availRegs & HOOK_FUNC_ARM64_REG_X10) {
        *regNo = 10;
    }
    else if (availRegs & HOOK_FUNC_ARM64_REG_X11) {
        *regNo = 11;
    }
    else if (availRegs & HOOK_FUNC_ARM64_REG_X12) {
        *regNo = 12;
    }
    else if (availRegs & HOOK_FUNC_ARM64_REG_X13) {
        *regNo = 13;
    }
    else if (availRegs & HOOK_FUNC_ARM64_REG_X14) {
        *regNo = 14;
    }
    else if (availRegs & HOOK_FUNC_ARM64_REG_X15) {
        *regNo = 15;
    }
    else {
        hook_func_set_error_message(funcHook, "All caller-saved registers are used.");
        return HOOK_FUNC_ERROR_NO_AVAILABLE_REGISTERS;
    }

    return 0;
}

static int hook_func_write_relative_4g_jump(HookFunc* funcHook, const uint32_t* src, const uint32_t* dst, uint32_t* out)
{
    intptr_t imm = C_ROUND_DOWN((size_t)dst, PAGE_SIZE) - C_ROUND_DOWN((size_t)src, PAGE_SIZE);
    uint32_t immlo = (uint32_t)(imm >> 12) & 0x03;
    uint32_t immhi = (uint32_t)(imm >> 14) & 0x7FFFFul;

    /* adrp x9, dst */
    out[0] = 0x90000009 | (immlo << 29) | (immhi << 5);
    /* br x9 */
    out[1] = 0xd61f0120;
    C_LOG_DEBUG("  Write relative +/-4G jump 0x%X -> 0x%X", (size_t) src, (size_t) dst);
    return 0;
}


static int hook_func_write_absolute_jump(HookFunc* funcHook, uint32_t* src, const uint32_t* dst, uint32_t availRegs)
{
    uint32_t regNo;
    int rv = to_reg_no(funcHook, availRegs, &regNo);
    if (rv != 0) {
        return rv;
    }
    /* ldr x9, +8 */
    src[0] = 0x58000040 | regNo;
    /* br x9 */
    src[1] = 0xd61f0120 | TO_RN(regNo);
    /* addr */
    *(const uint32_t**)(src + 2) = dst;
    C_LOG_DEBUG("  Write absolute jump 0x%x -> 0x%x\n", (size_t) src, (size_t) dst);

    return 0;
}

static int hook_func_write_jump_with_prehook(HookFunc* funcHook, HookFuncEntry* entry, const uint8_t* dst)
{
    static const uint32_t template[TRANSIT_CODE_SIZE] = TRANSIT_CODE_TEMPLATE;
    memcpy(entry->transit, template, sizeof(template));
    extern void hook_func_hook_caller_asm(void);
    *(void**)(entry->transit + TRANSIT_HOOK_CALLER_ADDR) = (void*) hook_func_hook_caller_asm;
    C_LOG_DEBUG("  Write jump 0x%X -> 0x%X with hook caller 0x%X\n", (size_t) entry->transit, (size_t) dst, (size_t) hook_func_hook_caller);

    return 0;
}

static size_t target_addr(size_t addr, uint32_t ins, uint8_t insnId)
{
    switch (insnId) {
    case HOOK_FUNC_ARM64_INSN_ADR:
        return addr + IMM_ADR_OFFSET(ins);
    case HOOK_FUNC_ARM64_INSN_ADRP:
        return C_ROUND_DOWN(addr, PAGE_SIZE) + (IMM_ADR_OFFSET(ins) << 12);
    case HOOK_FUNC_ARM64_INSN_B:
    case HOOK_FUNC_ARM64_INSN_BL:
        return addr + IMM26_OFFSET(ins);
    case HOOK_FUNC_ARM64_INSN_LDR:
    case HOOK_FUNC_ARM64_INSN_LDRSW:
    case HOOK_FUNC_ARM64_INSN_PRFM:
        if (ins & 0x20000000) { return 0; }
        /* FALLTHROUGH */
    case HOOK_FUNC_ARM64_INSN_B_cond:
    case HOOK_FUNC_ARM64_INSN_CBNZ:
    case HOOK_FUNC_ARM64_INSN_CBZ:
        return addr + IMM19_OFFSET(ins);
    case HOOK_FUNC_ARM64_INSN_TBNZ:
    case HOOK_FUNC_ARM64_INSN_TBZ:
        return addr + IMM14_OFFSET(ins);
    }

    return 0;
}

int hook_func_make_trampoline (HookFunc* funcHook, IpDisplacement* disp, const Insn* func, Insn* trampoline, size_t* trampolineSize)
{
    MakeTrampolineContext ctx;
    HookFuncDisAsm disAsm;
    int rv;
    const HookFuncInsn* insn;
    uint32_t avail_regs = HOOK_FUNC_ARM64_CORRUPTIBLE_REGS;
    size_t *literal_pool = (size_t*)(trampoline + LITERAL_POOL_OFFSET);

#define LDR_ADDR(regno, addr) do { \
    int imm19__ = (int)((size_t)literal_pool - (size_t)ctx.dst) >> 2; \
    *(literal_pool++) = (addr); \
    *(ctx.dst++) = 0x58000000 | TO_IMM19(imm19__) | (regno); \
} while (0)
#define BR_BY_REG(regno) do { \
    *(ctx.dst++) = 0xD61F0000 | TO_RN(regno); \
} while (0)

    memset(disp, 0, sizeof(*disp));
    memset(trampoline, 0, TRAMPOLINE_BYTE_SIZE);
    *trampolineSize = 0;
    ctx.hookFunc = funcHook;
    ctx.src = func;
    ctx.dstBase = ctx.dst = trampoline;

    rv = hook_func_disasm_init(&disAsm, funcHook, func, MAX_INSN_CHECK_SIZE, (size_t)func);
    if (rv != 0) {
        return rv;
    }

    C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  Original Instructions:\n");
    while ((rv = hook_func_disasm_next(&disAsm, &insn)) == 0) {
        HookFuncInsnInfo info = hook_func_disasm_arm64_insn_info(&disAsm, insn);
        uint32_t ins = *ctx.src;
        size_t addr;
        uint32_t regno;

        hook_func_disasm_log_instruction(&disAsm, insn);
        avail_regs &= ~info.regs;
        switch (info.insnId) {
        default:
            *(ctx.dst++) = ins;
            break;
        case HOOK_FUNC_ARM64_INSN_ADR:
            addr = (size_t)ctx.src + IMM_ADR_OFFSET(ins);
            // ldr xd, <label containing addr>
            LDR_ADDR(RD_REGNO(ins), addr);
            break;
        case HOOK_FUNC_ARM64_INSN_ADRP:
            addr = C_ROUND_DOWN((size_t)ctx.src, PAGE_SIZE) + (IMM_ADR_OFFSET(ins) << 12);
            // ldr xd, <label containing addr>
            LDR_ADDR(RD_REGNO(ins), addr);
            break;
        case HOOK_FUNC_ARM64_INSN_B_cond:
            addr = (size_t)ctx.src + IMM19_OFFSET(ins);
            rv = to_reg_no(funcHook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            if ((ins & 0x0F) != 0x0E) {
                // invert condition and skip two instructions
                *(ctx.dst++) = IMM19_RESET(RESET_AT(ins, 0)) | TO_IMM19(3) | INVERT_AT(ins, 0);
            }
            // ldr xt, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xn
            BR_BY_REG(regno);
            break;
        case HOOK_FUNC_ARM64_INSN_B:
        case HOOK_FUNC_ARM64_INSN_BL:
            addr = (size_t)ctx.src + IMM26_OFFSET(ins);
            rv = to_reg_no(funcHook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // ldr xt, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xn or blr xn
            *(ctx.dst++) = 0xD61F0000 | (ins & 0x80000000) >> 10 | TO_RN(regno);
            break;
        case HOOK_FUNC_ARM64_INSN_CBNZ:
        case HOOK_FUNC_ARM64_INSN_CBZ:
            addr = (size_t)ctx.src + IMM19_OFFSET(ins);
            rv = to_reg_no(funcHook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // invert condition and skip two instructions
            *(ctx.dst++) = IMM19_RESET(RESET_AT(ins, 24)) | INVERT_AT(ins, 24) | TO_IMM19(3);
            // ldr xd, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xd
            BR_BY_REG(regno);
            break;
        case HOOK_FUNC_ARM64_INSN_LDR:
        case HOOK_FUNC_ARM64_INSN_LDRSW:
        case HOOK_FUNC_ARM64_INSN_PRFM:
            if (ins & 0x20000000) {
                *(ctx.dst++) = ins;
            } else {
                addr = (size_t)ctx.src + IMM19_OFFSET(ins);
                rv = to_reg_no(funcHook, avail_regs, &regno);
                if (rv != 0) {
                    goto cleanup;
                }
                // ldr xn, <label containing addr>
                LDR_ADDR(regno, addr);
                switch (ins >> 24) {
                case 0x18: // 0001 1000 : LDR <Wt>, <label>
                    // ldr wt, xn
                    *(ctx.dst++) = 0xB9400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x58: // 0101 1000 : LDR <Xt>, <label>
                    // ldr xt, xn
                    *(ctx.dst++) = 0xF9400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x98: // 1001 1000 : LDRSW <Xt>, <label>
                    // ldrsw xt, xn
                    *(ctx.dst++) = 0xB9800000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x1C: // 0001 1100 : LDR <St>, <label> (32-bit variant)
                    // ldr st, xn
                    *(ctx.dst++) = 0xBD400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x5C: // 0101 1100 : LDR <Dt>, <label> (64-bit variant)
                    // ldr dt, xn
                    *(ctx.dst++) = 0xFD400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x9C: // 1001 1100 : LDR <Qt>, <label> (128-bit variant)
                    // ldr qt, xn
                    *(ctx.dst++) = 0x3DC00000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0xD8: // 1101 1000 : PRFM <prfop>, <label>
                    // prfm(immediate) <prfop>, [xn]
                    *(ctx.dst++) = 0xF9800000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                default:
                    hook_func_set_error_message(funcHook, "Unknonw instruction: 0x%08x", ins);
                    rv = HOOK_FUNC_ERROR_INTERNAL_ERROR;
                    goto cleanup;
                }
            }
            break;
        case HOOK_FUNC_ARM64_INSN_TBNZ:
        case HOOK_FUNC_ARM64_INSN_TBZ:
            addr = (size_t)ctx.src + IMM14_OFFSET(ins);
            rv = to_reg_no(funcHook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // invert condition and skip two instructions
            *(ctx.dst++) = IMM14_RESET(RESET_AT(ins, 24)) | INVERT_AT(ins, 24) | TO_IMM14(3);
            // ldr xd, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xd
            BR_BY_REG(regno);
            break;
        }
        ctx.src++;

        // special case
        if ((func[0] & 0xFC000000) == 0x14000000 && (func[1] & 0xFFFF0000) == 0) {
            // The first instruction is B (unconditional jump).
            // The second is UDF (permanently undefined).
            ctx.src = func + 2;
        }
        if (ctx.src - func >= REL4G_JUMP_SIZE) {
            rv = to_reg_no(funcHook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // ldr xn, #
            LDR_ADDR(regno, (size_t)ctx.src);
            // br xn
            BR_BY_REG(regno);

            *trampolineSize = ctx.dst - ctx.dstBase;
            while ((rv = hook_func_disasm_next(&disAsm, &insn)) == 0) {
                HookFuncInsnInfo infoT = hook_func_disasm_arm64_insn_info(&disAsm, insn);
                hook_func_disasm_log_instruction(&disAsm, insn);
                const Insn* target = (const Insn*) target_addr((size_t)ctx.src, *ctx.src, infoT.insnId);
                if (func < target && target < func + REL4G_JUMP_SIZE) {
                    /* jump to the hot-patched region. */
                    hook_func_set_error_message(funcHook, "instruction jumping back to the hot-patched region was found");
                    rv = HOOK_FUNC_ERROR_FOUND_BACK_JUMP;
                    goto cleanup;
                }
            }
            break;
        }
    }
    if (rv != HOOK_FUNC_ERROR_END_OF_INSTRUCTION) {
        goto cleanup;
    }
    rv = 0;
    if (ctx.src - func < REL4G_JUMP_SIZE) {
        hook_func_set_error_message(funcHook, "Too short instructions");
        rv = HOOK_FUNC_ERROR_TOO_SHORT_INSTRUCTIONS;
        goto cleanup;
    }

cleanup:
    hook_func_disasm_cleanup(&disAsm);

    return rv;
}

int hook_func_fix_code(HookFunc* funcHook, HookFuncEntry* entry, const IpDisplacement* disp)
{
    void *hookFunc = entry->hookFunc ? entry->hookFunc : entry->trampoline;

    /* func -> transit */
    hook_func_write_relative_4g_jump(funcHook, entry->targetFunc, entry->transit, entry->newCode);
    /* transit -> hook_func */
    if (entry->preHook) {
        hook_func_write_jump_with_prehook(funcHook, entry, hookFunc);
    }
    else {
        hook_func_write_absolute_jump(funcHook, entry->transit, hookFunc, HOOK_FUNC_ARM64_REG_X9);
    }
    return 0;
}

void* hook_func_arg_get_int_reg_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*)(argHandle->basePointer + 2  + pos);
}

void* hook_func_arg_get_flt_reg_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*) (argHandle->basePointer + (2 + 10) + 2 * pos);
}

void* hook_func_arg_get_stack_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*)(argHandle->basePointer + (2 + 10 + 16) + pos);
}

#endif