add_executable(test-hook1 test-hook1.c)
target_link_libraries(test-hook1 PUBLIC ${CAPS_LIBRARIES} hook-func)
target_include_directories(test-hook1 PUBLIC ${CAPS_INCLUDE_DIRS} ../src)