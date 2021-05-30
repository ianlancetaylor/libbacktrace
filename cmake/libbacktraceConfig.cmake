# Usage:
#
#find_package(libbacktrace REQUIRED)
#include_directories(${libbacktrace_INCLUDE_DIRS})
#target_link_libraries(app libbacktrace)

if(libbacktrace_CONFIG_INCLUDED)
  return()
endif()
set(libbacktrace_CONFIG_INCLUDED TRUE)

get_filename_component(SELF_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)
include(${SELF_DIR}/libbacktrace-targets.cmake)
get_filename_component(libbacktrace_INCLUDE_DIRS "${SELF_DIR}/.." ABSOLUTE)