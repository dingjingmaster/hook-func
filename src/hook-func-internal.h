//
// Created by dingjing on 25-6-16.
//

#ifndef hook_func_HOOK_FUNC_INTERNAL_H
#define hook_func_HOOK_FUNC_INTERNAL_H
#include "hook-func.h"

#include "arch-x86.h"
#include "arch-arm64.h"

#include "template.inc"


C_BEGIN_EXTERN_C
#define TRAMPOLINE_BYTE_SIZE                    (TRAMPOLINE_SIZE * sizeof(Insn))
#define page_size                               HookFuncPageSize
#define allocation_unit                         HookFuncAllocationUnit


typedef struct _HookMemState                    HookMemState;
typedef struct _HookFuncPage                    HookFuncPage;
typedef struct _HookFuncEntry                   HookFuncEntry;
typedef struct _HookFuncArgHandle               HookFuncHandle;

struct _HookFuncArgHandle
{
    const size_t*                       basePointer;
    uint32_t                            flags;
};

struct _HookMemState
{
    void*                               addr;
    size_t                              size;
#ifdef PLATFORM_WINDOWS
    DWORD                               protect;
#endif
};

/**
 * @brief 包含被Hook函数和Hook函数信息
 */
struct _HookFuncEntry
{
    Insn                                transit[TRANSIT_CODE_SIZE];
    void*                               origTargetFunc;
    void*                               targetFunc;
    void*                               hookFunc;
    HookFuncHook                        preHook;
    void*                               userData;
    uint32_t                            flags;
    uint32_t                            patchCodeSize;
    Insn                                trampoline[TRAMPOLINE_SIZE];
    Insn                                oldCode[MAX_PATCH_CODE_SIZE];
    Insn                                newCode[MAX_PATCH_CODE_SIZE];
};

/**
 * @brief 包含入口地址的内存页
 */
struct _HookFuncPage
{
#ifdef HOOK_FUNC_ENTRY_AT_PAGE_BOUNDARY
    HookFuncEntry                       entries[1];
#endif
    struct _HookFuncPage*               next;
    uint16_t                            used;
#ifndef HOOK_FUNC_ENTRY_AT_PAGE_BOUNDARY
    HookFuncEntry                       entries[1];
#endif
};

extern size_t gPageSize;
extern size_t gAllocationUnit;          // windows
extern const size_t gHookFuncSize;

void        hook_func_set_error_message     (HookFunc* funcHook, const char *fmt, ...);
void*       hook_func_hook_caller           (size_t transitAddr, const size_t* basePointer);

HookFunc*   hook_func_alloc                 (void);
int         hook_func_free                  (HookFunc* funcHook);
void*       hook_func_resolve_func          (HookFunc* funcHook, void* func);
int         hook_func_page_free             (HookFunc* funcHook, HookFuncPage* page);
int         hook_func_page_protect          (HookFunc* funcHook, HookFuncPage* page);
int         hook_func_page_unprotect        (HookFunc* funcHook, HookFuncPage* page);
int         hook_func_unprotect_end         (HookFunc* funcHook, const HookMemState* state);
int         hook_func_unprotect_begin       (HookFunc* funcHook, HookMemState* state, void* start, size_t len);
int         hook_func_page_alloc            (HookFunc* funcHook, HookFuncPage** pageOut, uint8_t* func, IpDisplacement* disp);

const char* hook_func_strerror              (int errNum, char *buf, size_t bufLen);
int         hook_func_fix_code              (HookFunc* funcHook, HookFuncEntry* entry, const IpDisplacement* disp);
int         hook_func_make_trampoline       (HookFunc* funcHook, IpDisplacement* disp, const Insn* func, Insn* trampoline, size_t* trampolineSize);

#ifdef ARCH_X86_64
int         hook_func_page_avail            (HookFunc* funcHook, HookFuncPage* page, int idx, uint8_t* addr, IpDisplacement* disp);
#else
#define     hook_func_page_avail            (funcHook, page, idx, addr, disp) (1)
#endif


C_END_EXTERN_C

#endif // hook_func_HOOK_FUNC_INTERNAL_H
