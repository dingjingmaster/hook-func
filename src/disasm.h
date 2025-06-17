//
// Created by dingjing on 25-6-16.
//

#ifndef hook_func_DIS_ASM_H
#define hook_func_DIS_ASM_H
#include "macros/macros.h"

#include <capstone/capstone.h>

#include "arch-x86.h"
#include "arch-arm64.h"


C_BEGIN_EXTERN_C

#define HOOK_FUNC_ERROR_END_OF_INSTRUCTION  -2
#define HOOK_FUNC_INSN_SIZE(insn)           ((insn)->size / sizeof(Insn))
#define HOOK_FUNC_INSN_ADDRESS(insn)        ((size_t)(insn)->address)
#define HOOK_FUNC_INSN_BRANCH_ADDRESS(insn) ((size_t)(insn)->detail->x86.operands[0].imm)


struct _HookFunc;
typedef cs_insn                     HookFuncInsn;
typedef struct _HookFuncDisAsm      HookFuncDisAsm;

struct _HookFuncDisAsm
{
    struct _HookFunc*               funcHook;
    csh                             handle;
    cs_insn*                        insns;
    size_t                          index;
    size_t                          count;
};

#if defined(ARCH_X86) || defined(ARCH_X86_64)
typedef struct
{
    Insn*                           addr;
    intptr_t                        rAddr;
    int                             offset;
    int                             size;
} RipRelative;

void    hook_func_disasm_x86_rip_relative   (HookFuncDisAsm* disAsm, const HookFuncInsn* insn, RipRelative* relDisp, RipRelative* relImm);
#endif

int     hook_func_disasm_init               (HookFuncDisAsm* disAsm, struct _HookFunc* hookFunc, const Insn* code, size_t codeSize, size_t address);
void    hook_func_disasm_cleanup            (HookFuncDisAsm* disAsm);
int     hook_func_disasm_next               (HookFuncDisAsm* disAsm, const HookFuncInsn** nextInsn);
void    hook_func_disasm_log_instruction    (HookFuncDisAsm* disAsm, const HookFuncInsn* insn);

#if defined(ARCH_ARM64)
HookFuncInsnInfo hook_func_disasm_arm64_insn_info   (HookFuncDisAsm* disAsm, const HookFuncInsn* insn);
#endif


C_END_EXTERN_C


#endif // hook_func_DIS_ASM_H
