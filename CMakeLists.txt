cmake_minimum_required(VERSION 3.19)
project(passl VERSION 1.0.0 LANGUAGES CXX)

add_library(${PROJECT_NAME} INTERFACE)

target_compile_definitions(${PROJECT_NAME} INTERFACE $<$<CONFIG:Debug>:__DEBUG__>)

include(GNUInstallDirs)

target_compile_options(${PROJECT_NAME}
  INTERFACE
  $<$<CONFIG:Debug>: -Wall -Wextra -Wpedantic>
  $<$<CONFIG:Release>: -O3>
)

file(GLOB_RECURSE SHARED_SRCS INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc)
target_sources(${PROJECT_NAME} INTERFACE ${SHARED_SRCS})

file(GLOB_RECURSE COPY_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/client/include/*.h
  ${CMAKE_CURRENT_SOURCE_DIR}/client/include/*.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/server/include/*.h
  ${CMAKE_CURRENT_SOURCE_DIR}/server/include/*.hpp
)

file(COPY ${COPY_HEADERS} DESTINATION ${CMAKE_BINARY_DIR}/include/${PROJECT_NAME}/)

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(lib/tancrypt)
add_subdirectory(tests)

target_include_directories(${PROJECT_NAME} INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)

target_link_libraries(${PROJECT_NAME} INTERFACE client)
target_link_libraries(${PROJECT_NAME} INTERFACE server)
target_link_libraries(${PROJECT_NAME} INTERFACE tancrypt)

enable_testing()
