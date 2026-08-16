project(testkit VERSION 1.0.0 LANGUAGES CXX)

file(GLOB_RECURSE SRC_FILES src/*.cc src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES})

# Basic memory bug
if(NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "(arm|aarch64)")
  target_compile_options(${PROJECT_NAME} 
    PRIVATE
    $<$<CONFIG:Debug>: -fsanitize=address -fno-omit-frame-pointer>
  )
  target_link_options(${PROJECT_NAME}
    PRIVATE
    $<$<CONFIG:Debug>: -fsanitize=address>
  )
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE passl)
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/include")

add_test(NAME "Libtest" COMMAND ${PROJECT_NAME})
# add_custom_command(TARGET passl-test POST_BUILD COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)


