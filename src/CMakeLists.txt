add_library(hook-func STATIC
        $<TARGET_OBJECTS:capstone>
        hook-func-internal.h
        log.c log.h
        disasm.c disasm.h
        arch-x86.c arch-x86.h
        hook-func.c hook-func.h
        arch-arm64.c arch-arm64.h
        asm/prehook-arm64-gas.S
        asm/prehook-x86_64-sysv.S
)
target_compile_options(hook-func PUBLIC -fPIC)
target_link_libraries(hook-func PUBLIC -pthread -ldl)
target_compile_definitions(hook-func PUBLIC
        -D C_LOG_TAG="hook-func"
        -D C_LOG_DIR="/tmp/hook-func.log"
)

add_library(hook-func-shared SHARED
        $<TARGET_OBJECTS:capstone>
        hook-func-internal.h
        log.c log.h
        disasm.c disasm.h
        arch-x86.c arch-x86.h
        hook-func.c hook-func.h
        arch-arm64.c arch-arm64.h
        asm/prehook-arm64-gas.S
        asm/prehook-x86_64-sysv.S
)
target_compile_options(hook-func-shared PUBLIC -fPIC)
target_link_libraries(hook-func-shared PUBLIC -pthread -ldl)
#target_include_directories(hook-func-shared PUBLIC )
target_compile_definitions(hook-func-shared PUBLIC
        -D C_LOG_TAG="hook-func"
        -D C_LOG_DIR="/tmp/hook-func.log"
)
