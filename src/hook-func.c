//
// Created by dingjing on 25-6-16.
//

#include "hook-func.h"

#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <c/clib.h>
#include <sys/mman.h>
#include <linux/limits.h>
#ifdef PLATFORM_LINUX
#include <elf.h>
#include <link.h>
#endif

#ifdef PLATFORM_APPLE
#include <stdlib.h>
#include <mach/mach.h>
#endif

#include "disasm.h"
#include "hook-func-internal.h"

#if !defined(MAP_ANONYMOUS) && !defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

#define HOOK_FUNC_MAX_ERROR_MESSAGE_LEN 200


/**
 * @brief 所有 Hook 函数的句柄
 */
struct _HookFunc
{
    int                     installed;                      // hook 是否安装成功
    HookFuncPage*           pageList;                       // hook 入口地址所在页
    char errorMessage[HOOK_FUNC_MAX_ERROR_MESSAGE_LEN];     // 错误信息
};

static HookFunc*        hook_func_create_internal   (void);
static int              hook_func_destroy_internal  (HookFunc* funcHook);
static void             flush_instruction_cache     (void *addr, size_t size);
static int              hook_func_install_internal  (HookFunc* funcHook, int flags);
static int              hook_func_uninstall_internal(HookFunc* funcHook, int flags);
static void             hook_func_log_trampoline    (HookFunc* funcHook, const Insn* trampoline, size_t trampolineSize);
static int              hook_func_prepare_internal  (HookFunc* funcHook, void** targetFunc, const HookFuncParams* params);
static int              get_page                    (HookFunc* funcHook, HookFuncPage** pageOut, uint8_t* addr, IpDisplacement* disp);


size_t gPageSize = 0;
static size_t gNumEntriesInPage = 0;
const size_t gHookFuncSize = sizeof(HookFunc);

#if defined(ARCH_X86_64) || defined(ARCH_ARM64)

typedef struct _MemoryMap MemoryMap;
static void memory_map_close(MemoryMap* mmap);
static int memory_map_open(HookFunc* funcHook, MemoryMap* mmap);
static int memory_map_next(MemoryMap* mmap, size_t *start, size_t *end);

#if defined(PLATFORM_LINUX)
static char scan_address(const char **str, size_t *addr_p)
{
    size_t addr = 0;
    const char *s = *str;

    while (1) {
        char c = *(s++);
        if ('0' <= c && c <= '9') {
            addr = (addr * 16) + (c - '0');
        }
        else if ('a' <= c && c <= 'f') {
            addr = (addr * 16) + (c - 'a' + 10);
        }
        else {
            *str = s;
            *addr_p = addr;
            return c;
        }
    }

    return 0;
}

struct _MemoryMap
{
    FILE *fp;
};

static int memory_map_open(HookFunc* funcHook, MemoryMap* mm)
{
    char buf[64] = {0};
    mm->fp = fopen("/proc/self/maps", "r");
    if (mm->fp == NULL) {
        hook_func_set_error_message(funcHook, "Failed to open /proc/self/maps (%s)",
                                   hook_func_strerror(errno, buf, sizeof(buf)));
        return HOOK_FUNC_ERROR_INTERNAL_ERROR;
    }
    return 0;
}

static int memory_map_next(MemoryMap* mm, size_t *start, size_t *end)
{
    char buf[PATH_MAX];
    const char *str = buf;

    if (fgets(buf, sizeof(buf), mm->fp) == NULL) {
        return -1;
    }
    if (scan_address(&str, start) != '-') {
        return -1;
    }
    if (scan_address(&str, end) != ' ') {
        return -1;
    }
    return 0;
}

static void memory_map_close(MemoryMap* mm)
{
    fclose(mm->fp);
}

#elif defined(PLATFORM_APPLE)

struct _MemoryMap
{
    mach_port_t task;
    vm_address_t addr;
};

static int memory_map_open(HookFunc* funchook, MemoryMap* mm)
{
    mm->task = mach_task_self();
    mm->addr = 0;
    return 0;
}

static int memory_map_next(MemoryMap* mm, size_t *start, size_t *end)
{
    vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = 0;

    if (vm_region_64(mm->task, &mm->addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object) != KERN_SUCCESS) {
        return -1;
    }
    *start = mm->addr;
    *end = mm->addr + size;
    mm->addr += size;
    return 0;
}

static void memory_map_close(MemoryMap* mm)
{
    return;
}

#else
#error unsupported OS
#endif

static int get_free_address(HookFunc* funchook, void *funcAddr, void *addrs[2])
{
    MemoryMap mm;
    size_t prevEnd = 0;
    size_t start, end;
    int rv;

    if ((rv = memory_map_open(funchook, &mm)) != 0) {
        return rv;
    }
    addrs[0] = addrs[1] = NULL;

    while (memory_map_next(&mm, &start, &end) == 0) {
        C_LOG_DEBUG("process map: %X - %X, prev_end=%X,addr={%X,%X},psz=%X",
                     start, end, prevEnd, (size_t)addrs[0], (size_t)addrs[1], gPageSize);
        if (prevEnd + gPageSize <= start) {
            if (start < (size_t) funcAddr) {
                size_t addr = start - gPageSize;
                if ((size_t)funcAddr - addr < INT32_MAX) {
                    /* unused memory region before func_addr. */
                    addrs[0] = (void*)addr;
                }
            }
            if ((size_t)funcAddr < prevEnd) {
                if (prevEnd - (size_t)funcAddr < INT32_MAX) {
                    /* unused memory region after func_addr. */
                    addrs[1] = (void*)prevEnd;
                }
                C_LOG_DEBUG("  -- Use address %p or %p for function %p",
                             addrs[0], addrs[1], funcAddr);
                memory_map_close(&mm);
                return 0;
            }
        }
        prevEnd = end;
    }
    if ((size_t)funcAddr < prevEnd) {
        if (prevEnd - (size_t)funcAddr < INT32_MAX) {
            /* unused memory region after func_addr. */
            addrs[1] = (void*)prevEnd;
        }
        C_LOG_DEBUG("Use address %p or %p for function %p", addrs[0], addrs[1], funcAddr);
        memory_map_close(&mm);
        return 0;
    }
    memory_map_close(&mm);
    hook_func_set_error_message(funchook, "Could not find a free region near %p", funcAddr);
    return HOOK_FUNC_ERROR_MEMORY_ALLOCATION;
}

#define SAFE_JUMP_DISTANCE(X, Y)  ((size_t)(X) - (size_t)(Y)) < (INT32_MAX - gPageSize)

#endif /* defined(CPU_64BIT) */


HookFunc * hook_func_create(void)
{
    HookFunc* handle = NULL;

    C_LOG_DEBUG("Enter %s", __func__);
    handle = hook_func_create_internal();
    C_LOG_DEBUG("Leave %s", __func__);

    return handle;
}

int hook_func_prepare(HookFunc * handle, void ** targetFunc, void * hookFunc)
{
    int rv = 0;
    void *origFunc = NULL;
    HookFuncParams params = { .hookFunc = hookFunc, };

    C_LOG_DEBUG("Enter hook_func_prepare(%p, %p, %p)", handle, targetFunc, hookFunc);
    origFunc = *targetFunc;
    rv = hook_func_prepare_internal(handle, targetFunc, &params);
    C_LOG_DEBUG("Leave hook_func_prepare(..., [%p->%p],...) => %d", origFunc, *targetFunc, rv);
    return rv;
}

int hook_func_prepare_with_params(HookFunc * handle, void ** targetFunc, const HookFuncParams * params)
{
    int rv = 0;
    void* origFunc = NULL;

    C_LOG_DEBUG("Enter hook_func_prepare_with_params(%p, %p, {%p, %p, %p})",
                 handle, targetFunc, params->hookFunc, params->preHook, params->userData);
    origFunc = *targetFunc;
    rv = hook_func_prepare_internal(handle, targetFunc, params);
    C_LOG_DEBUG("Leave hook_func_prepare_with_prehook(..., [%p->%p],...) => %d", origFunc, *targetFunc, rv);

    return rv;
}

int hook_func_install(HookFunc * handle, int flags)
{
    int rv = 0;

    C_LOG_DEBUG("Enter hook_func_install(%p, 0x%x)", handle, flags);
    rv = hook_func_install_internal(handle, flags);
    C_LOG_DEBUG("Leave hook_func_install() => %d", rv);

    return rv;
}

int hook_func_uninstall(HookFunc * handle, int flags)
{
    int rv = 0;

    C_LOG_DEBUG("Enter hook_func_uninstall(%p, 0x%x)", handle, flags);
    rv = hook_func_uninstall_internal(handle, flags);
    C_LOG_DEBUG("Leave hook_func_uninstall() => %d", rv);

    return rv;
}

int hook_func_destroy(HookFunc ** handle)
{
    int rv = 0;

    C_LOG_DEBUG("Enter funchook_destroy(%p)", handle);
    rv = hook_func_destroy_internal(*handle);
    *handle = NULL;
    C_LOG_DEBUG("Leave funchook_destroy() => %d", rv);

    return rv;
}

const char * hook_func_error_message(const HookFunc * handle)
{
    return handle->errorMessage;
}

void hook_func_set_error_message(HookFunc * funcHook, const char * fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsnprintf(funcHook->errorMessage, HOOK_FUNC_MAX_ERROR_MESSAGE_LEN - 1, fmt, args);
    va_end(args);
}

void* hook_func_hook_caller (size_t transitAddr, const size_t* basePointer)
{
    HookFuncEntry* entry = (HookFuncEntry*) (transitAddr - offsetof(HookFuncEntry, transit));
    HookFuncArgHandle argHandle = {
        .basePointer = basePointer,
        .flags = entry->flags,
    };
    HookFuncInfo info = {
        .origTargetFunc = entry->origTargetFunc,
        .targetFunc = entry->targetFunc,
        .trampolineFunc = entry->trampoline,
        .hookFunc = entry->hookFunc,
        .userData = entry->userData,
        .argHandles = &argHandle,
    };
    entry->preHook(&info);
    return entry->hookFunc ? entry->hookFunc : entry->trampoline;
}

HookFunc* hook_func_alloc (void)
{
    if (gPageSize == 0) {
        gPageSize = sysconf(_SC_PAGE_SIZE);
        C_LOG_DEBUG("page size = %d", gPageSize);
    }
    size_t size = C_ROUND_UP(gHookFuncSize, gPageSize);
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == (void*) -1) {
        return NULL;
    }
    return (HookFunc*) mem;
}

int hook_func_free (HookFunc* funcHook)
{
    size_t size = C_ROUND_UP(gHookFuncSize, gPageSize);
    munmap(funcHook, size);

    return 0;
}

int hook_func_page_alloc (HookFunc* funcHook, HookFuncPage** pageOut, uint8_t* func, IpDisplacement* disp)
{
#if defined(ARCH_X86_64) || defined(ARCH_ARM64)
    int loopCnt;

    /* Loop three times just to avoid rare cases such as
     * unused memory region is used between 'get_free_address()'
     * and 'mmap()'.
     */
    for (loopCnt = 0; loopCnt < 3; loopCnt++) {
        void *addrs[2];
        int rv = get_free_address(funcHook, func, addrs);
        int i;

        if (rv != 0) {
            return rv;
        }
        for (i = 1; i >= 0; i--) {
            /* Try to use addr[1] (unused memory region after `func`)
             * and then addr[0] (before `func`)
             */
            if (addrs[i] == NULL) {
                continue;
            }
            *pageOut = mmap(addrs[i], gPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (SAFE_JUMP_DISTANCE(func, *pageOut) || SAFE_JUMP_DISTANCE(*pageOut, func)) {
                C_LOG_DEBUG("  allocate page %p (size=%%X)", *pageOut, gPageSize);
                return 0;
            }
            if (*pageOut == MAP_FAILED) {
                char errbuf[128] = {0};
                hook_func_set_error_message(funcHook, "mmap failed(addr=%p): %s", addrs[i], hook_func_strerror(errno, errbuf, sizeof(errbuf)));
                return HOOK_FUNC_ERROR_MEMORY_ALLOCATION;
            }
            C_LOG_DEBUG("  try to allocate %p but %p (size=%%X)", addrs[i], *pageOut, gPageSize);
            munmap(*pageOut, gPageSize);
        }
    }
    hook_func_set_error_message(funcHook, "Failed to allocate memory in unused regions");
    return HOOK_FUNC_ERROR_MEMORY_ALLOCATION;
#else
    char errbuf[128];

    *pageOut = mmap(NULL, gPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*pageOut != MAP_FAILED) {
        C_LOG_DEBUG("  allocate page %p (size=%%X)", *pageOut, gPageSize);
        return 0;
    }
    hook_func_set_error_message(funcHook, "mmap failed: %s", hook_func_strerror(errno, errbuf, sizeof(errbuf)));
    return HOOK_FUNC_ERROR_MEMORY_ALLOCATION;
#endif
}

int hook_func_page_free (HookFunc* funcHook, HookFuncPage* page)
{
    char errBuf[128] = {0};
    int rv = munmap(page, gPageSize);

    if (rv == 0) {
        C_LOG_DEBUG(" deallocate page %p (size=%X)", page, gPageSize);
        return 0;
    }
    hook_func_set_error_message(funcHook, "Failed to deallocate page %p (size=%X, error=%s)",
                               page, gPageSize,
                               hook_func_strerror(errno, errBuf, sizeof(errBuf)));
    return HOOK_FUNC_ERROR_MEMORY_FUNCTION;
}

int hook_func_page_protect (HookFunc* funcHook, HookFuncPage* page)
{
    char errBuf[128] = {0};
    int rv = mprotect(page, gPageSize, PROT_READ | PROT_EXEC);

    if (rv == 0) {
        C_LOG_DEBUG("protect page %p (size=%X)", page, gPageSize);
        return 0;
    }
    hook_func_set_error_message(funcHook, "Failed to protect page %p (size=%X, error=%s)",
                               page, gPageSize,
                               hook_func_strerror(errno, errBuf, sizeof(errBuf)));
    return HOOK_FUNC_ERROR_MEMORY_FUNCTION;
}

int hook_func_page_unprotect (HookFunc* funcHook, HookFuncPage* page)
{
    char errBuf[128] = {0};
    int rv = mprotect(page, gPageSize, PROT_READ | PROT_WRITE);
    if (rv == 0) {
        C_LOG_DEBUG("  unprotect page %p (size=%X)", page, gPageSize);
        return 0;
    }
    hook_func_set_error_message(funcHook, "Failed to unprotect page %p (size=%X, error=%s)",
                               page, gPageSize,
                               hook_func_strerror(errno, errBuf, sizeof(errBuf)));
    return HOOK_FUNC_ERROR_MEMORY_FUNCTION;
}

int hook_func_unprotect_begin(HookFunc * funcHook, HookMemState* state, void* start, size_t len)
{
    int rv = 0;
    char errBuf[128] = {0};
    static int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    size_t sAddr = C_ROUND_DOWN((size_t) start, gPageSize);

    state->addr = (void*)sAddr;
    state->size = len + (size_t)start - sAddr;
    C_LOG_DEBUG("stat->size = %ld", state->size);
    state->size = C_ROUND_UP(state->size, gPageSize);
    C_LOG_DEBUG("start: %p, len: %ld, sAddr: %p, addr: %p, size: %ld",
        start, len, sAddr, state->addr, state->size);
    rv = mprotect(state->addr, state->size, prot);
    if (rv == 0) {
        C_LOG_DEBUG("unprotect memory %p (size=%lX, prot=read,write%s) <- %p (size=%lX)",
                     state->addr, state->size, (prot & PROT_EXEC) ? ",exec" : "", start, len);
        return 0;
    }
    else {
        C_LOG_WARNING("error: %d -- %s", errno, strerror(errno));
    }

    if (rv == -1 && errno == EACCES && (prot & PROT_EXEC)) {
        rv = mprotect(state->addr, state->size, PROT_READ | PROT_WRITE);
        if (rv == 0) {
            prot = PROT_READ | PROT_WRITE;
            C_LOG_DEBUG("unprotect memory %p (size=%lX, prot=read,write) <- %p (size=%lX)",
                         state->addr, state->size, start, len);
            return 0;
        }
    }
    hook_func_set_error_message(funcHook, "Failed to unprotect memory %p (size=%lX, prot=read,write%s) <- %p (size=%lX, error=%s)",
                               state->addr, state->size, (prot & PROT_EXEC) ? ",exec" : "", start, len,
                               hook_func_strerror(errno, errBuf, sizeof(errBuf)));
    return HOOK_FUNC_ERROR_MEMORY_FUNCTION;
}

int hook_func_unprotect_end(HookFunc * funcHook, const HookMemState * state)
{
    char errBuf[128] = {0};
    int rv = mprotect(state->addr, state->size, PROT_READ | PROT_EXEC);
    if (rv == 0) {
        C_LOG_DEBUG("protect memory %p (size=%X, prot=read,exec)", state->addr, state->size);
        return 0;
    }
    hook_func_set_error_message(funcHook, "Failed to protect memory %p (size=%X, prot=read,exec, error=%s)",
                               state->addr, state->size,
                               hook_func_strerror(errno, errBuf, sizeof(errBuf)));
    return HOOK_FUNC_ERROR_MEMORY_FUNCTION;
}

void* hook_func_resolve_func(HookFunc * funcHook, void * func)
{
#ifdef __GLIBC__
    struct link_map *lmap, *lm;
    const ElfW(Ehdr) *ehdr;
    const ElfW(Dyn) *dyn;
    const ElfW(Sym) *symtab = NULL;
    const ElfW(Sym) *symtabEnd = NULL;
    const char *strtab = NULL;
    size_t strtabSize = 0;
    int i = 0;

    lmap = NULL;
    for (lm = _r_debug.r_map; lm != NULL; lm = lm->l_next) {
        if ((void*)lm->l_addr <= func) {
            if (lmap == NULL) {
                C_LOG_DEBUG("Found '%p' dynamic library!", func);
                lmap = lm;
            }
            else if (lmap->l_addr > lm->l_addr) {
                lmap = lm;
            }
        }
    }
    if (lmap == NULL) {
        C_LOG_WARNING("NOT FOUND func '%p' library!", func);
        return func;
    }

    if (lmap->l_addr != 0) {
        ehdr = (ElfW(Ehdr) *)lmap->l_addr;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
            C_LOG_WARNING("Not a valid ELF module %s.", lmap->l_name);
            return func;
        }
        if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
          C_LOG_WARNING("ELF type is neither ET_EXEC nor ET_DYN.");
          return func;
        }
    }
    C_LOG_DEBUG("link_map addr=%p, name=%s", (void*) lmap->l_addr, lmap->l_name);

    dyn = lmap->l_ld;
    for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:
            symtab = (const ElfW(Sym)*) dyn[i].d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = (const char*) dyn[i].d_un.d_ptr;
            break;
        case DT_STRSZ:
            strtabSize = dyn[i].d_un.d_val;
            break;
        }
    }
    C_RETURN_VAL_IF_FAIL(symtab && strtab, func);

    symtabEnd = (const ElfW(Sym)*) strtab;
    while (symtab < symtabEnd) {
        if (symtab->st_name >= strtabSize) {
            break;
        }
        if (ELF64_ST_TYPE(symtab->st_info) == STT_FUNC
            && symtab->st_size == 0 && (void*)symtab->st_value == func) {
            void *fn = dlsym(RTLD_DEFAULT, strtab + symtab->st_name);
            if (fn == func) {
                fn = dlsym(RTLD_NEXT, strtab + symtab->st_name);
            }
            if (fn != NULL) {
                C_LOG_DEBUG("Change %s address from %p to %p", strtab + symtab->st_name, func, fn);
                func = fn;
            }
            break;
        }
        symtab++;
    }
#endif
    return func;
}

static HookFunc* hook_func_create_internal (void)
{
    HookFunc* hf = hook_func_alloc();
    if (hf == NULL) {
        return NULL;
    }
    if (gNumEntriesInPage == 0) {
#ifdef HOOK_FUNC_ENTRY_AT_PAGE_BOUNDARY
        gNumEntriesInPage = 1;
#else
        gNumEntriesInPage = (gPageSize - offsetof(HookFuncPage, entries)) / sizeof(HookFuncEntry);
#endif
        C_LOG_DEBUG("\n  page_size=%X\n  num_entries_in_page=%X", gPageSize, gNumEntriesInPage);
    }

    return hf;
}

const char* hook_func_strerror(int errNum, char *buf, size_t bufLen)
{
#ifdef GNU_SPECIFIC_STRERROR_R
    /* GNU-specific version */
    return strerror_r(errnum, buf, buflen);
#else
    /* XSI-compliant version */
    if (strerror_r(errNum, buf, bufLen) != 0) {
        snprintf(buf, bufLen, "errno %d", errNum);
    }
    return buf;
#endif
}

static int hook_func_prepare_internal(HookFunc* funcHook, void** targetFunc, const HookFuncParams* params)
{
    void *func = *targetFunc;
    Insn trampoline[TRAMPOLINE_SIZE];
    size_t trampolineSize;
    IpDisplacement disp;
    HookFuncPage* page = NULL;
    HookFuncEntry* entry = NULL;
    int rv = 0;

    if (funcHook->installed) {
        hook_func_set_error_message(funcHook, "Could not modify already-installed hook func handle.");
        return HOOK_FUNC_ERROR_ALREADY_INSTALLED;
    }
    func = hook_func_resolve_func(funcHook, func);
    rv = hook_func_make_trampoline(funcHook, &disp, func, trampoline, &trampolineSize);
    if (rv != 0) {
        C_LOG_DEBUG("failed to make trampoline");
        return rv;
    }
    rv = get_page(funcHook, &page, func, &disp);
    if (rv != 0) {
        C_LOG_DEBUG("failed to get page");
        return rv;
    }
    entry = &page->entries[page->used];
    /* fill members */
    entry->origTargetFunc = *targetFunc;
    entry->targetFunc = func;
    entry->hookFunc = params->hookFunc;
    entry->preHook = params->preHook;
    entry->userData = params->userData;
    entry->flags = params->flags;
    entry->patchCodeSize = MAX_PATCH_CODE_SIZE;
    memcpy(entry->trampoline, trampoline, TRAMPOLINE_BYTE_SIZE);
    memcpy(entry->oldCode, func, sizeof(entry->oldCode));

    hook_func_fix_code(funcHook, entry, &disp);
    hook_func_log_trampoline(funcHook, entry->trampoline, trampolineSize);
#ifdef ARCH_ARM64
    int i;
    for (i = 0; i < LITERAL_POOL_NUM; i++) {
        size_t *addr = (size_t*)(entry->trampoline + LITERAL_POOL_OFFSET + i * 2);
        if (*addr != 0) {
            C_LOG_DEBUG("    %X : 0x%X", (size_t)addr, *addr);
        }
    }
#endif

    /* Just in case though I think this is unnecessary. */
    flush_instruction_cache(entry->trampoline, sizeof(entry->trampoline));
#if defined(ARCH_X86_64) || defined(ARCH_ARM64)
    flush_instruction_cache(entry->transit, sizeof(entry->transit));
#endif

    page->used++;
    *targetFunc = (void*)entry->trampoline;

    return 0;
}

static int get_page (HookFunc* funcHook, HookFuncPage** pageOut, uint8_t* addr, IpDisplacement* disp)
{
    int rv = 0;
    HookFuncPage* page = NULL;

    for (page = funcHook->pageList; page != NULL; page = page->next) {
        if (page->used < gNumEntriesInPage && hook_func_page_avail(funcHook, page, page->used, addr, disp)) {
            /* Reuse allocated page. */
            *pageOut = page;
            return 0;
        }
    }
    rv = hook_func_page_alloc(funcHook, &page, addr, disp);
    if (rv != 0) {
        return rv;
    }
    if (!hook_func_page_avail(funcHook, page, page->used, addr, disp)) {
        hook_func_set_error_message(funcHook, "Could not allocate memory near address %p", addr);
        hook_func_page_free(funcHook, page);
        return HOOK_FUNC_ERROR_NO_SPACE_NEAR_TARGET_ADDR;
    }
    page->used = 0;
    page->next = funcHook->pageList;
    funcHook->pageList = page;
    *pageOut = page;

    return 0;
}

static void hook_func_log_trampoline(HookFunc* funcHook, const Insn* trampoline, size_t trampolineSize)
{
    HookFuncDisAsm disAsm;
    const HookFuncInsn* insn;

    C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  Trampoline Instructions:");
    if (hook_func_disasm_init(&disAsm, funcHook, trampoline, trampolineSize, (size_t)trampoline) != 0) {
        int i;
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  Failed to decode trampoline\n    ");
        for (i = 0; i < TRAMPOLINE_SIZE; i++) {
            C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, " %02x", trampoline[i]);
        }
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "\n");
        return;
    }
    while (hook_func_disasm_next(&disAsm, &insn) == 0) {
        hook_func_disasm_log_instruction(&disAsm, insn);
    }
    hook_func_disasm_cleanup(&disAsm);
}

static void flush_instruction_cache(void *addr, size_t size)
{
#if defined __GNUC__
    __builtin___clear_cache((char*)addr, (char*)addr + size);
#elif defined _WIN32
    FlushInstructionCache(GetCurrentProcess(), addr, size);
#else
#error unsupported OS or compiler
#endif
}

static int hook_func_install_internal(HookFunc* funcHook, int flags)
{
    HookFuncPage* page = NULL;

    if (funcHook->installed) {
        C_LOG_WARNING("Hooked function already installed");
        return HOOK_FUNC_ERROR_ALREADY_INSTALLED;
    }

    for (page = funcHook->pageList; page != NULL; page = page->next) {
        int i = 0;
        int rv = hook_func_page_protect(funcHook, page);
        if (rv != 0) {
            C_LOG_WARNING("Hooked function page protection failed");
            return rv;
        }

        for (i = 0; i < page->used; i++) {
            HookFuncEntry* entry = &page->entries[i];
            size_t patchCodeByteSize = entry->patchCodeSize * sizeof(Insn);
            HookMemState state;
            int rv1 = hook_func_unprotect_begin(funcHook, &state, entry->targetFunc, patchCodeByteSize);
            if (rv1 != 0) {
                C_LOG_WARNING("Hooked function unprotect_begin failed");
                return rv1;
            }
            memcpy(entry->targetFunc, entry->newCode, patchCodeByteSize);
            rv1 = hook_func_unprotect_end(funcHook, &state);
            if (rv1 != 0) {
                C_LOG_WARNING("Hooked function unprotect_end failed");
                return rv1;
            }
            flush_instruction_cache(entry->targetFunc, patchCodeByteSize);
            HookFuncDisAsm disAsm;
            const HookFuncInsn* insn;
            C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "Patched Instructions:");
            hook_func_disasm_init(&disAsm, funcHook, entry->targetFunc, entry->patchCodeSize + 5, (size_t)entry->targetFunc);
            while ((rv = hook_func_disasm_next(&disAsm, &insn)) == 0) {
                hook_func_disasm_log_instruction(&disAsm, insn);
            }
            hook_func_disasm_cleanup(&disAsm);
        }
    }
    funcHook->installed = 1;
    C_LOG_INFO("");

    return 0;
}

static int hook_func_uninstall_internal(HookFunc* funcHook, int flags)
{
    HookFuncPage* page = NULL;

    if (!funcHook->installed) {
        return HOOK_FUNC_ERROR_NOT_INSTALLED;
    }

    for (page = funcHook->pageList; page != NULL; page = page->next) {
        int i = 0;
        for (i = 0; i < page->used; i++) {
            HookFuncEntry* entry = &page->entries[i];
            size_t patchCodeByteSize = entry->patchCodeSize * sizeof(Insn);
            HookMemState state;
            int rv = hook_func_unprotect_begin(funcHook, &state, entry->targetFunc, patchCodeByteSize);

            if (rv != 0) {
                return rv;
            }
            memcpy(entry->targetFunc, entry->oldCode, patchCodeByteSize);
            rv = hook_func_unprotect_end(funcHook, &state);
            if (rv != 0) {
                return rv;
            }
            flush_instruction_cache(entry->targetFunc, patchCodeByteSize);
        }
        hook_func_page_unprotect(funcHook, page);
    }
    funcHook->installed = 0;

    return 0;
}

static int hook_func_destroy_internal(HookFunc* funcHook)
{
    HookFuncPage* page, *pageNext;

    if (funcHook == NULL) {
        return -1;
    }
    if (funcHook->installed) {
        return HOOK_FUNC_ERROR_ALREADY_INSTALLED;
    }
    for (page = funcHook->pageList; page != NULL; page = pageNext) {
        pageNext = page->next;
        hook_func_page_free(funcHook, page);
    }

    hook_func_free(funcHook);

    return 0;
}

