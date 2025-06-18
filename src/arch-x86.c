//
// Created by dingjing on 25-6-16.
//

#include "arch-x86.h"

#if defined(ARCH_X86_64) || defined(ARCH_X86)
#include <stdio.h>
#include <c/clib.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disasm.h"
#include "hook-func-internal.h"


#define NOP_INSTRUCTION                             0x90

typedef struct _MakeTrampolineContext               MakeTrampolineContext;

struct _MakeTrampolineContext
{
    HookFunc*                                       funcHook;
    IpDisplacement*                                 ripDisp;
    const uint8_t*                                  src;
    const uint8_t*                                  dstBase;
    uint8_t*                                        dst;
};

#if defined(ARCH_X86)
static int handle_x86_get_pc_thunk              (MakeTrampolineContext* ctx, const HookFuncInsn* di);
static int handle_x86_get_pc_by_call_and_pop    (MakeTrampolineContext* ctx, const HookFuncInsn* di);
#else
#define handle_x86_get_pc_thunk(ctx, di) (0)
#define handle_x86_get_pc_by_call_and_pop(ctx, di) (0)
#endif

static int handle_rip_relative(MakeTrampolineContext* ctx, const RipRelative* rel, size_t insnSize);

static int hook_func_write_relative_2g_jump(HookFunc* funcHook, const uint8_t* src, const uint8_t* dst, uint8_t* out)
{
    out[0] = 0xe9;
    *(int*)(out + 1) = (int)(dst - (src + 5));
    C_LOG_DEBUG("Write relative +/-2G jump 0x%X -> 0x%X", (size_t) src, (size_t) dst);

    return 0;
}

static int hook_func_write_jump_with_prehook(HookFunc* funcHook, HookFuncEntry* entry, const uint8_t* dst)
{
    static const char template[TRANSIT_CODE_SIZE] = TRANSIT_CODE_TEMPLATE;
    memcpy(entry->transit, template, sizeof(template));
    extern void hook_func_hook_caller_asm(void);
    *(void**)(entry->transit + TRANSIT_HOOK_CALLER_ADDR) = (void*) hook_func_hook_caller_asm;
    C_LOG_DEBUG("  Write jump 0x%X -> 0x%X with hook caller 0x%X\n", (size_t) entry->transit, (size_t) dst, (size_t) hook_func_hook_caller);

    return 0;
}

#ifdef ARCH_X86_64
static int hook_func_write_absolute_jump(HookFunc* funcHook, uint8_t* src, const uint8_t* dst)
{
    src[0] = 0xFF;
    src[1] = 0x25;
    src[2] = 0x00;
    src[3] = 0x00;
    src[4] = 0x00;
    src[5] = 0x00;
    *(const uint8_t**)(src + 6) = dst;
    C_LOG_DEBUG("  Write absolute jump 0x%X -> 0x%X\n", (size_t) src, (size_t) dst);

    return 0;
}

static int hook_func_within_32bit_relative(const uint8_t* src, const uint8_t* dst)
{
    int64_t diff = (int64_t) (dst - src);

    return (INT32_MIN <= diff && diff <= INT32_MAX);
}

static int hook_func_relative_2g_jump_avail(const uint8_t *src, const uint8_t *dst)
{
    return hook_func_within_32bit_relative(src + 5, dst);
}

#endif

int hook_func_make_trampoline(HookFunc* funcHook, IpDisplacement* disp, const uint8_t* func, uint8_t* trampoline, size_t* trampolineSize)
{
    int rv = 0;
    HookFuncDisAsm disAsm;
    const HookFuncInsn* insn;
    MakeTrampolineContext ctx;

    memset(disp, 0, sizeof(*disp));
    memset(trampoline, NOP_INSTRUCTION, TRAMPOLINE_SIZE);
    *trampolineSize = 0;
    ctx.funcHook = funcHook;
    ctx.ripDisp = disp;
    ctx.src = func;
    ctx.dstBase = ctx.dst = trampoline;

    rv = hook_func_disasm_init(&disAsm, funcHook, func, MAX_INSN_CHECK_SIZE, (size_t)func);
    C_RETURN_VAL_IF_FAIL(0 == rv, rv);

    C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "Original Instructions:");
    // 或取一条汇编指令，保存到 insn 指针
    while ((rv = hook_func_disasm_next(&disAsm, &insn)) == 0) {
        RipRelative relDisp;
        RipRelative relImm;

        hook_func_disasm_log_instruction(&disAsm, insn);
        if (handle_x86_get_pc_thunk(&ctx, insn)) {
            ;
        }
        else if (handle_x86_get_pc_by_call_and_pop(&ctx, insn)) {
            if ((rv = hook_func_disasm_next(&disAsm, &insn)) == 0) {
                hook_func_disasm_log_instruction(&disAsm, insn);
            }
        }
        else {
            const size_t insnSize = HOOK_FUNC_INSN_SIZE(insn);
            memcpy(ctx.dst, ctx.src, insnSize);
            hook_func_disasm_x86_rip_relative(&disAsm, insn, &relDisp, &relImm);
            rv = handle_rip_relative(&ctx, &relDisp, insnSize);
            if (rv != 0) {
                goto cleanup;
            }
            rv = handle_rip_relative(&ctx, &relImm, insnSize);
            if (rv != 0) {
                goto cleanup;
            }
            ctx.src += insnSize;
            ctx.dst += insnSize;
        }

        if (ctx.src - func >= REL2G_JUMP_SIZE) {
            ctx.dst[0] = 0xe9; /* unconditional jump */
            disp->disp[0].dstAddr = ctx.src;
            disp->disp[0].srcAddrOffset = (ctx.dst - ctx.dstBase) + 5;
            disp->disp[0].posOffset = (ctx.dst - ctx.dstBase) + 1;
            *trampolineSize = (ctx.dst - ctx.dstBase) + 5;
            while ((rv = hook_func_disasm_next(&disAsm, &insn)) == 0) {
                hook_func_disasm_log_instruction(&disAsm, insn);
                hook_func_disasm_x86_rip_relative(&disAsm, insn, &relDisp, &relImm);
                if (func < relImm.addr && relImm.addr < func + REL2G_JUMP_SIZE) {
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
    /* too short function. Check whether NOP instructions continue. */
    while (ctx.src - func < REL2G_JUMP_SIZE) {
        if (*ctx.src != NOP_INSTRUCTION) {
            hook_func_set_error_message(funcHook, "Too short instructions");
            rv = HOOK_FUNC_ERROR_TOO_SHORT_INSTRUCTIONS;
            goto cleanup;
        }
        ctx.src++;
    }

cleanup:
    hook_func_disasm_cleanup(&disAsm);

    return rv;
}

#ifndef handle_x86_get_pc_thunk
/* special cases to handle "call __x86.get_pc_thunk.??"
 * If the target instructions are "movl (%esp), %???; ret",
 * use "movl addr + 5, %???" instead.
 */
static int handle_x86_get_pc_thunk(MakeTrampolineContext* ctx, const HookFuncInsn* insn)
{
    uint32_t eip = 0;
    const char *regName = NULL;

    if (*ctx->src == 0xe8) {
        uint32_t first_4_bytes = *(uint32_t*) HOOK_FUNC_INSN_BRANCH_ADDRESS(insn);

        eip = HOOK_FUNC_INSN_ADDRESS(insn) + 5;
        switch (first_4_bytes) {
        case 0xc324048b: /* 8b 04 24 c3: movl (%esp), %eax; ret */
            regName = "ax";
            *ctx->dst = 0xb8; /*         movl addr + 5, %eax */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3241c8b: /* 8b 1c 24 c3: movl (%esp), %ebx; ret */
            regName = "bx";
            *ctx->dst = 0xbb; /*         movl addr + 5, %ebx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3240c8b: /* 8b 0c 24 c3: movl (%esp), %ecx; ret */
            regName = "cx";
            *ctx->dst = 0xb9; /*         movl addr + 5, %ecx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc324148b: /* 8b 14 24 c3: movl (%esp), %edx; ret */
            regName = "dx";
            *ctx->dst = 0xba; /*         movl addr + 5, %edx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc324348b: /* 8b 34 24 c3: movl (%esp), %esi; ret */
            regName = "si";
            *ctx->dst = 0xbe; /*         movl addr + 5, %esi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3243c8b: /* 8b 3c 24 c3: movl (%esp), %edi; ret */
            regName = "di";
            *ctx->dst = 0xbf; /*         movl addr + 5, %edi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3242c8b: /* 8b 2c 24 c3: movl (%esp), %ebp; ret */
            regName = "bp";
            *ctx->dst = 0xbd; /*         movl addr + 5, %ebp */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        }
    }
    return 0;

fixed:
    C_LOG_DEBUG("      use 'MOV E%c%c, 0x%x' instead of 'CALL __x86.get_pc_thunk.%s'",
                 regName[0] + 'A' - 'a',
                 regName[1] + 'A' - 'a',
                 eip, regName);
    ctx->dst += 5;
    ctx->src += 5;
    return 1;
}
#endif

#ifndef handle_x86_get_pc_by_call_and_pop
static int handle_x86_get_pc_by_call_and_pop(MakeTrampolineContext* ctx, const HookFuncInsn* insn)
{
    uint32_t eip = 0;
    const char *regName = NULL;

    if (*ctx->src == 0xe8 && *(uint32_t*)(ctx->src + 1) == 0) {
        eip = HOOK_FUNC_INSN_ADDRESS(insn) + 5;
        switch (*(ctx->src + 5)) {
        case 0x58: /* pop %eax */
            regName = "EAX";
            *ctx->dst = 0xb8; /* movl addr + 5, %eax */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5b: /* pop %ebx */
            regName = "EBX";
            *ctx->dst = 0xbb; /* movl addr + 5, %ebx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x59: /* pop %ecx */
            regName = "ECX";
            *ctx->dst = 0xb9; /* movl addr + 5, %ecx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5a: /* pop %edx */
            regName = "EDX";
            *ctx->dst = 0xba; /* movl addr + 5, %edx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5e: /* pop %esi */
            regName = "ESI";
            *ctx->dst = 0xbe; /* movl addr + 5, %esi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5f: /* pop %edi */
            regName = "EDI";
            *ctx->dst = 0xbf; /* movl addr + 5, %edi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5d: /* pop %ebp */
            regName = "EBP";
            *ctx->dst = 0xbd; /* movl addr + 5, %ebp */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        }
    }
    return 0;

fixed:
    C_LOG_DEBUG("      use 'MOV %s, 0x%x' instead of 'CALL 0x%x; POP %s'", regName, eip, eip, regName);
    ctx->dst += 5;
    ctx->src += 6;

    return 1;
}
#endif

/*
 * Fix RIP-relative address in an instruction
 */
static int handle_rip_relative(MakeTrampolineContext* ctx, const RipRelative* rel, size_t insnSize)
{
    if (rel->size == 32) {
        if (*(int32_t*)(ctx->dst + rel->offset) != (uint32_t)rel->rAddr) {
            /* sanity check.
             * reach here if opsiz and/or disp_offset are incorrectly
             * estimated.
             */
            hook_func_set_error_message(ctx->funcHook, "Invalid ip-relative offset %d. The value at the offset should be %08x but %08x",
                         rel->offset, (uint32_t)rel->rAddr, *(int32_t*)(ctx->dst + rel->offset));
            return HOOK_FUNC_ERROR_IP_RELATIVE_OFFSET;
        }
        ctx->ripDisp->disp[1].dstAddr = rel->addr;
        ctx->ripDisp->disp[1].srcAddrOffset = (size_t) (ctx->dst - ctx->dstBase) + insnSize;
        ctx->ripDisp->disp[1].posOffset = (ctx->dst - ctx->dstBase) + rel->offset;
    }
    else if (rel->size != 0) {
        hook_func_set_error_message(ctx->funcHook, "Could not fix ip-relative address. The size is not 32.");
        return HOOK_FUNC_ERROR_CANNOT_FIX_IP_RELATIVE;
    }

    return 0;
}

int hook_func_fix_code(HookFunc* funcHook, HookFuncEntry* entry, const IpDisplacement* disp)
{
    Insn* srcAddr;
    uint32_t* offsetAddr;
    void *hookFunc = entry->hookFunc ? entry->hookFunc : entry->trampoline;

    memset(entry->newCode, NOP_INSTRUCTION, sizeof(entry->newCode));
    entry->patchCodeSize = disp->disp[0].dstAddr - (uint8_t*)entry->targetFunc;
    if (entry->preHook) {
        hook_func_write_relative_2g_jump(funcHook, entry->targetFunc, entry->transit, entry->newCode);
        hook_func_write_jump_with_prehook(funcHook, entry, hookFunc);
#ifdef ARCH_X86_64
    }
    else if (!hook_func_relative_2g_jump_avail(entry->targetFunc, hookFunc)) {
        hook_func_write_relative_2g_jump(funcHook, entry->targetFunc, entry->transit, entry->newCode);
        hook_func_write_absolute_jump(funcHook, entry->transit, hookFunc);
#endif
    }
    else {
        hook_func_write_relative_2g_jump(funcHook, entry->targetFunc, hookFunc, entry->newCode);
        entry->transit[0] = 0;
    }

    /* fix rip-relative offsets */
    srcAddr = entry->trampoline + disp->disp[0].srcAddrOffset;
    offsetAddr = (uint32_t*)(entry->trampoline + disp->disp[0].posOffset);
    *offsetAddr = (uint32_t)(disp->disp[0].dstAddr - srcAddr);
    if (disp->disp[1].dstAddr != 0) {
        srcAddr = entry->trampoline + disp->disp[1].srcAddrOffset;
        offsetAddr = (uint32_t*)(entry->trampoline + disp->disp[1].posOffset);
        *offsetAddr = (uint32_t)(disp->disp[1].dstAddr - srcAddr);
    }
    return 0;
}

#ifdef ARCH_X86_64
int hook_func_page_avail(HookFunc* funcHook, HookFuncPage* page, int idx, uint8_t *addr, IpDisplacement* disp)
{
    HookFuncEntry* entry = &page->entries[idx];
    const uint8_t *src;
    const uint8_t *dst;

    if (!hook_func_relative_2g_jump_avail(addr, entry->transit)) {
        C_LOG_DEBUG("  could not jump function %p to transit %p", addr, entry->transit);
        return 0;
    }
    src = entry->trampoline + disp->disp[0].srcAddrOffset;
    dst = disp->disp[0].dstAddr;
    if (!hook_func_within_32bit_relative(src, dst)) {
        C_LOG_DEBUG("  could not jump trampoline %p to function %p", src, dst);
        return 0;
    }
    src = entry->trampoline + disp->disp[1].srcAddrOffset;
    dst = disp->disp[1].dstAddr;
    if (dst != 0 && !hook_func_within_32bit_relative(src, dst)) {
        C_LOG_DEBUG("  could not make 32-bit relative address from %p to %p\n", src, dst);
        return 0;
    }
    return 1;
}
#endif

#ifdef ARCH_X86_64
#ifdef PLATFORM_WINDOWS
#define INT_REG_OFFSET (0x80 / 8)
#define FLT_REG_OFFSET (0x60 / 8)
#define STACK_OFFSET 6
#else
#define INT_REG_OFFSET (0xc0 / 8)
#define FLT_REG_OFFSET (0x80 / 8)
#define STACK_OFFSET 2
#endif

void* hook_func_arg_get_int_reg_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*) (argHandle->basePointer - INT_REG_OFFSET + pos);
}

void* hook_func_arg_get_flt_reg_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*)(argHandle->basePointer - FLT_REG_OFFSET + 2 * pos);
}

void* hook_func_arg_get_stack_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*)(argHandle->basePointer + STACK_OFFSET + pos);
}
#endif

#ifdef ARCH_X86
void* hook_func_arg_get_int_reg_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*)(argHandle->basePointer - 2 + pos);
}

void* hook_func_arg_get_stack_addr(const HookFuncArgHandle* argHandle, int pos)
{
    return (void*)(argHandle->basePointer + 2 + pos);
}
#endif


#endif
