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


typedef int (*Add) (int a, int b);

#if 0
0x56191a3a3229: endbr64
0x56191a3a322d: push rbp
0x56191a3a322e: mov rbp, rsp
0x56191a3a3231: mov dword ptr [rbp - 4], edi
0x56191a3a3234: mov dword ptr [rbp - 8], esi
0x56191a3a3237: mov edx, dword ptr [rbp - 4]
0x56191a3a323a: mov eax, dword ptr [rbp - 8]
0x56191a3a323d: add eax, edx
0x56191a3a323f: pop rbp
0x56191a3a3240: ret
#endif
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
    Add t = add;
    cs_insn* insns = NULL;

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

        printf("0x%"PRId64"\n", (long int) t);
        for (size_t i = 0; i < count; i++) {
            printf("0x%"PRIx64": %s %s\n", insns[i].address, insns[i].mnemonic, insns[i].op_str);
        }
    }

    return 0;
}
