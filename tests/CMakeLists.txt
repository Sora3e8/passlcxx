project(testkit VERSION 1.0.0 LANGUAGES CXX)

file(GLOB_RECURSE SRC_FILES src/*.cc src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES})

target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME "Libtest" COMMAND ${PROJECT_NAME})
# add_custom_command(TARGET passl-test POST_BUILD COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)


