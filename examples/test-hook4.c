//
// Created by dingjing on 25-6-17.
//
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <capstone.h>


#define REL2G_JUMP_SIZE             5
#define MAX_INSN_LEN                16
#define FINISHED                    100
#define MAX_INSN_CHECK_SIZE         256
#define NOP_INSTRUCTION             0x90
#define INSN_SIZE(insn)             ((insn)->size / sizeof(uint8_t))
#define MAX_PATCH_CODE_SIZE         (REL2G_JUMP_SIZE + MAX_INSN_LEN - 1)
#define TRAMPOLINE_SIZE             (REL2G_JUMP_SIZE + (MAX_INSN_LEN - 1) + REL2G_JUMP_SIZE)


static inline int dis_asm_next(size_t* index, size_t count, cs_insn* inInsn, cs_insn** nextInsn)
{
    if (*index < count) {
        *nextInsn = &inInsn[(*index)++];
        return 0;
    }

    return FINISHED;
}

static inline void dis_asm_x86_rip_relative (cs_insn* insnTmp,
    cs_insn** immAddr, intptr_t* immRAddr, int* immOffset, int* immSize,
    cs_insn** dispAddr, intptr_t* dispRAddr, int* dispOffset, int* dispSize)
{
    cs_x86* x86 = &insnTmp->detail->x86;

    if (x86->encoding.imm_offset != 0) {
        for (int i = 0; i < insnTmp->detail->groups_count; i++) {
            if (insnTmp->detail->groups[i] == X86_GRP_BRANCH_RELATIVE) {
                intptr_t imm = 0;
                if (x86->encoding.imm_size == 4) {
                    imm = *(int32_t*) (insnTmp->bytes + x86->encoding.imm_offset);
                }
                else if (x86->encoding.imm_size == 1) {
                    imm = *(int8_t*) (insnTmp->bytes + x86->encoding.imm_offset);
                }

                *immAddr = (cs_insn*) (size_t) (insnTmp->address + insnTmp->size + imm);
                *immRAddr = imm;
                *immSize = x86->encoding.imm_size * 8;
                *immOffset = x86->encoding.imm_offset;
                break;
            }
        }
    }

    if (x86->encoding.imm_offset != 0) {
        for (int i = 0; i < x86->op_count; i++) {
            const cs_x86_op* op = &x86->operands[i];
            if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
                *dispAddr = (cs_insn*) (size_t) (insnTmp->address + insnTmp->size + x86->disp);
                *dispRAddr = (intptr_t) x86->disp;
                *dispSize = x86->encoding.disp_size * 8;
                *dispOffset = x86->encoding.disp_offset;
            }
        }
    }
}

static int handle_rip_relative(intptr_t* dispRAddr, int* dispOffset, int* dispSize, size_t insnSize)
{
    // if (*dispSize == 32) {
    //     if (*(int32_t*)(ctx->dst + *dispOffset) != (uint32_t) *dispRAddr) {
    //         return -1;
    //     }
    //     ctx->ripDisp->disp[1].dstAddr = dispRAddr;
    //     ctx->ripDisp->disp[1].srcAddrOffset = (size_t) (ctx->dst - ctx->dstBase) + insnSize;
    //     ctx->ripDisp->disp[1].posOffset = (ctx->dst - ctx->dstBase) + rel->offset;
    // }
    // else if (dispSize != 0) {
    //     return -2;
    // }

    return 0;
}


typedef int (*Add) (int a, int b);

int add(int a, int b)
{
    return a + b;
}

int hook_add(int a, int b)
{
    return -1;
}

void* thread_handle(void* data)
{
    while (1) {
        printf ("%d + %d = %d\n", 1, 2, add(1, 2));
        sleep(1);
    }

    return NULL;
}

int main (int argc, char* argv[])
{
    int rv = 0;
    Add t = add;
    size_t idx = 0;
    pthread_t threadID;
    cs_insn* insns = NULL;
    size_t trampolineSize = 0;
    char trampoline[TRAMPOLINE_SIZE] = {0};

    memset(trampoline, NOP_INSTRUCTION, TRAMPOLINE_SIZE);

    pthread_create(&threadID, NULL, thread_handle, NULL);

    sleep(2);

    printf("start Hook!\n");

    // Hook 核心代码
    {
        csh handle;
        cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
        if (0 != err) {
            printf("cs_open failed, err=%s\n", cs_strerror(err));
            return -1;
        }

        err = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        if (0 != err) {
            printf("cs_option failed, err=%s\n", cs_strerror(err));
            cs_close(&handle);
            return -2;
        }

        const size_t count = cs_disasm(handle, (const uint8_t*) t, MAX_INSN_CHECK_SIZE, (size_t) t, 0, &insns);
        if (count == 0) {
            printf("cs_disasm failed, err=%s\n", cs_strerror(err));
            cs_close(&handle);
            return -3;
        }


        cs_insn* insnTmp = insns;
        uint8_t* dst = NULL;
        const uint8_t* src = (uint8_t*) t;
        while (0 == (rv = dis_asm_next(&idx, count, insnTmp, &insnTmp))) {
            const size_t insnSize = INSN_SIZE(insnTmp);
            printf("insn size = %ld\n", insnSize);
            memcpy(dst, src, insnSize);

            cs_insn* dispAddr;
            intptr_t dispRAddr;
            int      dispOffset;
            int      dispSize;

            cs_insn* immAddr;
            intptr_t immRAddr;
            int      immOffset;
            int      immSize;

            dis_asm_x86_rip_relative (insnTmp, &immAddr, &immRAddr, &immOffset, &immSize, &dispAddr, &dispRAddr, &dispOffset, &dispSize);



        }

    }






    pthread_join(threadID, NULL);

    return 0;
}
