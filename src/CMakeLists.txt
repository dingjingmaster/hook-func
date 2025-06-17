add_library(hook-func STATIC
        hook-func-internal.h
        disasm.c disasm.h
        arch-x86.c arch-x86.h
        hook-func.c hook-func.h
        arch-arm64.c arch-arm64.h
        asm/prehook-arm64-gas.S
        asm/prehook-x86_64-sysv.S
)
target_compile_options(hook-func PUBLIC -fPIC)
target_link_libraries(hook-func PUBLIC ${CLIB_LIBRARIES} -pthread -ldl)
target_include_directories(hook-func PUBLIC ${CLIB_INCLUDE_DIRS})
target_compile_definitions(hook-func PUBLIC
        -D C_STRLEN
        -D C_STR_HAS_PREFIX
        -D C_STR_HAS_SUFFIX
        -D C_LOG_TAG="hook-func"
        -D C_LOG_DIR="/tmp/hook-func.log"
)

add_library(hook-func-shared SHARED
        hook-func-internal.h
        disasm.c disasm.h
        arch-x86.c arch-x86.h
        hook-func.c hook-func.h
        arch-arm64.c arch-arm64.h
        asm/prehook-arm64-gas.S
        asm/prehook-x86_64-sysv.S
)
target_compile_options(hook-func-shared PUBLIC -fPIC)
target_link_libraries(hook-func-shared PUBLIC ${CLIB_LIBRARIES} ${CAPS_LIBRARIES} -pthread -ldl)
target_include_directories(hook-func-shared PUBLIC ${CLIB_INCLUDE_DIRS} ${CAPS_INCLUDE_DIRS})
target_compile_definitions(hook-func-shared PUBLIC
        -D C_STRLEN
        -D C_STR_HAS_PREFIX
        -D C_STR_HAS_SUFFIX
        -D C_LOG_TAG="hook-func"
        -D C_LOG_DIR="/tmp/hook-func.log"
)
