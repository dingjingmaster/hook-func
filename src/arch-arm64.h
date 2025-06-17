//
// Created by dingjing on 25-6-16.
//

#ifndef hook_func_ARCH_ARM_64_H
#define hook_func_ARCH_ARM_64_H
#include "macros/macros.h"

C_BEGIN_EXTERN_C

#ifdef ARCH_ARM64

#define REL4G_JUMP_SIZE                     2
#define MAX_INSN_CHECK_SIZE                 64
#define LITERAL_POOL_OFFSET                 (3 * REL4G_JUMP_SIZE + 2)
#define LITERAL_POOL_NUM                    (REL4G_JUMP_SIZE + 1)
#define TRAMPOLINE_SIZE                     (LITERAL_POOL_OFFSET + 2 * LITERAL_POOL_NUM)
#define MAX_PATCH_CODE_SIZE                 REL4G_JUMP_SIZE
#define HOOK_FUNC_ENTRY_AT_PAGE_BOUNDARY    1

#define HOOK_FUNC_ARM64_REG_X9              (1u<<9)
#define HOOK_FUNC_ARM64_REG_X10             (1u<<10)
#define HOOK_FUNC_ARM64_REG_X11             (1u<<11)
#define HOOK_FUNC_ARM64_REG_X12             (1u<<12)
#define HOOK_FUNC_ARM64_REG_X13             (1u<<13)
#define HOOK_FUNC_ARM64_REG_X14             (1u<<14)
#define HOOK_FUNC_ARM64_REG_X15             (1u<<15)
#define HOOK_FUNC_ARM64_CORRUPTIBLE_REGS    (HOOK_FUNC_ARM64_REG_X9 \
    | HOOK_FUNC_ARM64_REG_X10 | HOOK_FUNC_ARM64_REG_X11 \
    | HOOK_FUNC_ARM64_REG_X12 | HOOK_FUNC_ARM64_REG_X13 \
    | HOOK_FUNC_ARM64_REG_X14 | HOOK_FUNC_ARM64_REG_X15)

typedef uint32_t                            Insn;
typedef struct _IpDisplacement              IpDisplacement;
typedef struct _HookFuncInsnInfo            HookFuncInsnInfo;

typedef enum
{
    HOOK_FUNC_ARM64_INSN_OTHER = 0,
    HOOK_FUNC_ARM64_INSN_ADR,
    HOOK_FUNC_ARM64_INSN_ADRP,
    HOOK_FUNC_ARM64_INSN_B,
    HOOK_FUNC_ARM64_INSN_BL,
    HOOK_FUNC_ARM64_INSN_B_cond,
    HOOK_FUNC_ARM64_INSN_CBNZ,
    HOOK_FUNC_ARM64_INSN_CBZ,
    HOOK_FUNC_ARM64_INSN_LDR,
    HOOK_FUNC_ARM64_INSN_LDRSW,
    HOOK_FUNC_ARM64_INSN_PRFM,
    HOOK_FUNC_ARM64_INSN_TBNZ,
    HOOK_FUNC_ARM64_INSN_TBZ,
} HookFuncArm64InsnId;

struct _IpDisplacement
{
    int                     dummy;
};

struct _HookFuncInsnInfo
{
    HookFuncArm64InsnId     insnId;
    uint32_t                regs;
};

#endif

C_END_EXTERN_C

#endif // hook_func_ARCH_ARM_64_H
