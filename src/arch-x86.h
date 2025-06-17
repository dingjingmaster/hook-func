//
// Created by dingjing on 25-6-16.
//

#ifndef hook_func_ARCH_X_86_H
#define hook_func_ARCH_X_86_H
#include <stdint.h>

#if defined(ARCH_X86_64) || defined(ARCH_X86)
#define REL2G_JUMP_SIZE             5
#define MAX_INSN_LEN                16
#define MAX_INSN_CHECK_SIZE         256
#define MAX_PATCH_CODE_SIZE         (REL2G_JUMP_SIZE + MAX_INSN_LEN - 1)
#define TRAMPOLINE_SIZE             (REL2G_JUMP_SIZE + (MAX_INSN_LEN - 1) + REL2G_JUMP_SIZE)


typedef uint8_t                     Insn;
typedef struct _IpDisplacement      IpDisplacement;
typedef struct _IpDisplacementEntry IpDisplacementEntry;


struct _IpDisplacementEntry
{
    const Insn*                     dstAddr;
    intptr_t                        srcAddrOffset;
    intptr_t                        posOffset;
};

struct _IpDisplacement
{
    IpDisplacementEntry             disp[2];
};

#endif

#endif // hook_func_ARCH_X_86_H
