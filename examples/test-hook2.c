//
// Created by dingjing on 25-6-17.
//
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "../src/hook-func-internal.h"


int main (void)
{
    gPageSize = sysconf(_SC_PAGE_SIZE);
    const int num = (gPageSize - offsetof(HookFuncPage, entries)) / sizeof(HookFuncEntry);

    printf(" size: %ld\n", sizeof(HookFuncPage));
    printf(" hook func entry: %ld\n", sizeof(HookFuncEntry));
    printf(" offset: %ld\n", offsetof(HookFuncPage, entries));
    printf(" page size: %ld\n num: %d\n", gPageSize, num);

    return 0;
}