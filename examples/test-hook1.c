//
// Created by dingjing on 25-6-17.
//
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include "hook-func.h"


typedef int (*Add) (int a, int b);

int add(int a, int b)
{
    return a + b;
}

Add t = add;

int hook_add(int a, int b)
{
    printf("true: %d -- ", t(a, b));
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
    pthread_t threadID;

    pthread_create(&threadID, NULL, thread_handle, NULL);

    sleep(5);

    printf("start Hook!\n");

    HookFunc* hf = hook_func_create();
    if (!hf) {
        printf("hook_func_create error!\n");
        return 1;
    }

    int ret = hook_func_prepare(hf, (void**) &t, hook_add);
    if (ret != 0) {
        printf("hook_func_prepare error!\n");
        return 2;
    }
    // 其它 prepare

    ret = hook_func_install(hf, 0);
    if (0 != ret) {
        printf("hook_func_install error!\n");
        return 3;
    }

    sleep(10);

    printf ("Stop Hook!\n");

    // uninstall
    ret = hook_func_uninstall(hf, 0);
    if (0 != ret) {
        printf("hook_func_uninstall error!\n");
        return 4;
    }

    ret = hook_func_destroy(&hf);
    if (0 != ret) {
        printf("hook_func_destroy error!\n");
        return 5;
    }

    pthread_join(threadID, NULL);

    return 0;
}
