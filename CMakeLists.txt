cmake_minimum_required(VERSION 3.25)
project(pecore VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "pecore parses loaded images through <Windows.h>; build it on Windows.")
endif()

option(PECORE_BUILD_TESTS "Build the doctest suite" ${PROJECT_IS_TOP_LEVEL})
option(PECORE_BUILD_EXAMPLES "Build the pedump example" ${PROJECT_IS_TOP_LEVEL})

add_library(pecore INTERFACE)
add_library(pecore::pecore ALIAS pecore)
target_include_directories(pecore INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(pecore INTERFACE cxx_std_23)

if(PECORE_BUILD_TESTS)
  enable_testing()
  add_executable(pecore_tests tests/PeCoreTests.cpp)
  target_link_libraries(pecore_tests PRIVATE pecore::pecore)
  if(MSVC)
    # C5285: vendored doctest specialises std::tuple, which MSVC 19.50+ flags.
    target_compile_options(pecore_tests PRIVATE /W4 /WX /permissive- /wd5285)
    # The suite reads its own CodeView record, so every config links one in.
    target_link_options(pecore_tests PRIVATE /DEBUG)
  endif()
  add_test(NAME pecore_tests COMMAND pecore_tests)
endif()

if(PECORE_BUILD_EXAMPLES)
  add_executable(pedump examples/pedump.cpp)
  target_link_libraries(pedump PRIVATE pecore::pecore)
  if(MSVC)
    target_compile_options(pedump PRIVATE /W4 /WX /permissive-)
  endif()
endif()

install(DIRECTORY include/ DESTINATION include)
install(TARGETS pecore EXPORT pecoreTargets)
install(EXPORT pecoreTargets NAMESPACE pecore:: DESTINATION lib/cmake/pecore)
