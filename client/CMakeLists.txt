cmake_minimum_required(VERSION 3.19)
project(client VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)

file(GLOB_RECURSE SRC_FILES *.cc *.cpp)

add_library(${PROJECT_NAME} STATIC ${SRC_FILES})

set_target_properties(${PROJECT_NAME}
  PROPERTIES
  CMAKE_CXX_STANDARD 11
  CMAKE_CXX_STANDARD_REQUIRED ON
)

# For crc32
find_package(ZLIB REQUIRED)
target_link_libraries("${PROJECT_NAME}" PRIVATE ZLIB::ZLIB)

target_include_directories(${PROJECT_NAME}
  PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
 )
