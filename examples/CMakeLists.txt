add_executable(test-hook1 test-hook1.c)
target_link_libraries(test-hook1 PUBLIC ${CAPS_LIBRARIES} hook-func)
target_include_directories(test-hook1 PUBLIC ${CAPS_INCLUDE_DIRS} ../src)

add_executable(test-hook2 test-hook2.c)
target_link_libraries(test-hook2 PUBLIC ${CAPS_LIBRARIES} hook-func)
target_include_directories(test-hook2 PUBLIC ${CAPS_INCLUDE_DIRS} ../src)

add_executable(test-hook3 test-hook3.c)
target_link_libraries(test-hook3 PUBLIC ${CAPS_LIBRARIES} hook-func)
target_include_directories(test-hook3 PUBLIC ${CAPS_INCLUDE_DIRS} ../src)

add_executable(test-hook4 test-hook4.c)
target_link_libraries(test-hook4 PUBLIC ${CAPS_LIBRARIES} hook-func)
target_include_directories(test-hook4 PUBLIC ${CAPS_INCLUDE_DIRS} ../src)
