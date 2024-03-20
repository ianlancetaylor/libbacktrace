# CMakeLists.txt -- Backtrace configure script.
# Copyright (C) 2012-2018 Free Software Foundation, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) The name of the author may not be used to
#     endorse or promote products derived from this software without
#     specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.5)

project(backtrace C)

# This file is a work in progress - some things may be broken,
#so feel free to fix 'em by looking at configure.ac

# Automake uses -frandom-seed initialized with file name of given file
# but AFAIK it can't be done on CMake, so here's always same seed
set(CMAKE_CXX_FLAGS "-DHAVE_CONFIG_H -funwind-tables -frandom-seed=mySeed -W -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wmissing-format-attribute -Wcast-qual -g -O2")
set(CMAKE_C_FLAGS "-DHAVE_CONFIG_H -funwind-tables -frandom-seed=mySeed -W -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wmissing-format-attribute -Wcast-qual -g -O2")

set(sources
    atomic.c dwarf.c fileline.c posix.c print.c sort.c state.c config.h
)
set(export_headers
    ${CMAKE_CURRENT_SOURCE_DIR}/backtrace.h
    ${CMAKE_CURRENT_BINARY_DIR}/backtrace-supported.h
)

if(CMAKE_COMPILER_IS_GNUCC)
    set(_GNU_SOURCE 1)
    set(BACKTRACE_SUPPORTED 1)
    
    # Assume multi-threaded environment
    set(BACKTRACE_SUPPORTS_THREADS 1)

    # Assume ELF/DWARF, meaning that BACKTRACE_SUPPORTS_DATA is hard-coded on.
    set(BACKTRACE_SUPPORTS_DATA 1)
        
    find_package(ZLIB)
    if(ZLIB_FOUND)
        set(HAVE_LIBZ 1)
        set(HAVE_ZLIB 1)
    else()
        set(HAVE_LIBZ 0)
        set(HAVE_ZLIB 0)
    endif()
    
    if(WIN32)
        # Typical MinGW config
        # DWARF2 exception handling could be detected based on parsing gcc --version
        set(BACKTRACE_USES_MALLOC 1)
        set(BACKTRACE_ELF_SIZE unused)
        set(BACKTRACE_XCOFF_SIZE unused)

        # TODO do those tests using CMake
        set(HAVE_ATOMIC_FUNCTIONS 1)
        set(HAVE_CLOCK_GETTIME 1)
        set(HAVE_DECL_STRNLEN 1)
        set(HAVE_DLFCN_H 0)
        set(HAVE_DL_ITERATE_PHDR 0)
        set(HAVE_FCNTL 0)
        set(HAVE_GETEXECNAME 0)
        set(HAVE_GETIPINFO 1)
        set(HAVE_INTTYPES_H 1)
        set(HAVE_LINK_H 0)
        set(HAVE_LOADQUERY 0)
        set(HAVE_LSTAT 0)
        set(HAVE_MEMORY_H 1)
        set(HAVE_READLINK 0)
        set(HAVE_STDINT_H 1)
        set(HAVE_STDLIB_H 1)
        set(HAVE_STRINGS_H 1)
        set(HAVE_STRING_H 1)
        set(HAVE_SYNC_FUNCTIONS 1)
        set(HAVE_SYS_LDR_H 0)
        set(HAVE_SYS_MMAN_H 0)
        set(HAVE_SYS_STAT_H 1)
        set(HAVE_SYS_TYPES_H 1)
        set(HAVE_UNISTD_H 1)

        set(sources "${sources};backtrace.c;simple.c")
        set(FORMAT_FILE "pecoff.c")
        set(VIEW_FILE "read.c")
        set(ALLOC_FILE "alloc.c")
    else()
        # TODO make this code work on Windows - it's proper configure replacement
        include(CheckIncludeFiles)
        include(CheckFunctionExists)
        include(CheckCSourceCompiles)
        include(CheckLibraryExists)
        include(CheckCCompilerFlag)

        # Check some headers
        check_include_files("unistd.h" HAVE_UNISTD_H)
        check_include_files("sys/types.h" HAVE_SYS_TYPES_H)
        check_include_files("sys/stat.h" HAVE_SYS_STAT_H)
        check_include_files("string.h" HAVE_STRING_H)
        check_include_files("strings.h" HAVE_STRINGS_H)
        check_include_files("stdlib.h" HAVE_STDLIB_H)
        check_include_files("stdint.h" HAVE_STDINT_H)
        check_include_files("inttypes.h" HAVE_INTTYPES_H)
        check_include_files("memory.h" HAVE_MEMORY_H)
        check_include_files("dlfcn.h" HAVE_DLFCN_H)

        # Check some functions
        check_function_exists(
            "readlink" HAVE_READLINK CMAKE_REQUIRED_INCLUDES "unistd.h"
        )
        check_function_exists(
            "lstat" HAVE_READLINK CMAKE_REQUIRED_INCLUDES "sys/stat.h"
        )
        check_function_exists(
            "strnlen" HAVE_DECL_STRNLEN CMAKE_REQUIRED_INCLUDES "string.h"
        )

        # Check unwind
        check_include_files("unwind.h" UNWIND_HEADER_FOUND)
        check_function_exists(
            "_Unwind_Backtrace" UNWIND_FN_FOUND CMAKE_REQUIRED_INCLUDES
        )
        if((${UNWIND_HEADER_FOUND}) AND (${UNWIND_FN_FOUND}))
            set(sources "${sources};backtrace.c;simple.c")
        else()
            set(sources "${sources};nounwind.c")
            set(BACKTRACE_SUPPORTED 0)
        endif()

        # Check UnwindGetIPInfo
        set(oldFlags ${CMAKE_REQUIRED_FLAGS})
        set(CMAKE_REQUIRED_FLAGS "-Werror-implicit-function-declaration")
        check_c_source_compiles("
            #include \"unwind.h\"

            struct _Unwind_Context *context;
            int ip_before_insn = 0;

            int main(void) {
                return _Unwind_GetIPInfo (context, &ip_before_insn);
            }
        " HAVE_GETIPINFO)
        set(CMAKE_REQUIRED_FLAGS ${oldFlags})

        set(oldFlags ${CMAKE_REQUIRED_FLAGS})
        set(CMAKE_REQUIRED_FLAGS "-funwind-tables")
        CHECK_C_COMPILER_FLAG("" unwind_tables_supported)
        if(unwind_tables_supported)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -funwind-tables")
        endif()
        set(CMAKE_REQUIRED_FLAGS ${oldFlags})

        # Check threads
        # TODO configure.ac checks hppa*-*-hpux* stuff, dunno what it is
        check_c_source_compiles("
            int i;
            int main(void) {
                __sync_bool_compare_and_swap (&i, i, i);
                __sync_lock_test_and_set (&i, 1);
                __sync_lock_release (&i);
                return 0;
            }
        " HAVE_SYNC_FUNCTIONS)
        if(${HAVE_SYNC_FUNCTIONS})
            set(BACKTRACE_SUPPORTS_THREADS 1)
        endif()

        # Check __atomic support
        check_c_source_compiles("
            int i;
            int main(void) {
                __atomic_load_n (&i, __ATOMIC_ACQUIRE);
                __atomic_store_n (&i, 1, __ATOMIC_RELEASE);
                return 0;
            }
        " HAVE_ATOMIC_FUNCTIONS)

        # The library needs to be able to read the executable itself.
        # Determine executable format (elf32/elf64/pecoff)
        if(("${CMAKE_EXECUTABLE_FORMAT}" STREQUAL "ELF"))
            math(EXPR BACKTRACE_ELF_SIZE "${CMAKE_SIZEOF_VOID_P} * 8")
            set(filetype "elf${BACKTRACE_ELF_SIZE}")
            set(FORMAT_FILE "elf.c")
            set(BACKTRACE_SUPPORTS_DATA 1)
        else()
            # TODO detect pecoff/xcoff in some way - especially on MinGW
            message(
                FATAL_ERROR "Unknown executable format: '${CMAKE_EXECUTABLE_FORMAT}'"
            )
        endif()
        message(STATUS "Executable format: ${filetype}")

        # mmap support
        check_include_files("sys/mman.h" HAVE_SYS_MMAN_H)
        if(HAVE_SYS_MMAN_H)
            # TODO port from configure.ac: spu-*-*|*-*-msdosdjgpp
            check_function_exists(
                "mmap" have_mmap CMAKE_REQUIRED_INCLUDES "sys/mman.h"
            )
        endif()
        if(NOT have_mmap)
            set(VIEW_FILE "read.c")
            set(ALLOC_FILE "alloc.c")
        else()
            set(VIEW_FILE "mmapio.c")
            check_c_source_compiles("
                #include <sys/mman.h>
                #if !defined(MAP_ANONYMOUS) && !defined(MAP_ANON)
                    #error no MAP_ANONYMOUS
                #endif
            " use_mmap_for_alloc)
            if(use_mmap_for_alloc)
                set(ALLOC_FILE "mmap.c")
                SET(BACKTRACE_USES_MALLOC 0)
            else()
                set(ALLOC_FILE "alloc.c")
                SET(BACKTRACE_USES_MALLOC 1)
            endif()

            # Check for dl_iterate_phdr
            check_include_files("link.h" HAVE_LINK_H)
            if(HAVE_LINK_H)
                # TODO port from configure.ac: *-*-solaris2.10*
                check_function_exists(
                    "dl_iterate_phdr" HAVE_DL_ITERATE_PHDR
                    CMAKE_REQUIRED_INCLUDES "link.h"
                )
            endif()

            # Check for loadquery.
            check_include_files("sys/ldr.h" HAVE_SYS_LDR_H)
            check_function_exists(
                "loadquery" HAVE_LOADQUERY CMAKE_REQUIRED_INCLUDES "sys/ldr.h"
            )
            
            # Check for fcntl function.
            check_function_exists(
                "fcntl" HAVE_FCNTL CMAKE_REQUIRED_INCLUDES "fcntl.h"
            )
            
            # Check for getexecname function.
            check_function_exists(
                "getexecname" HAVE_GETEXECNAME CMAKE_REQUIRED_INCLUDES "stdlib.h"
            )

            # Check for the clock_gettime function.
            check_library_exists(rt clock_gettime "time.h" HAVE_CLOCK_GETTIME)
            if (HAVE_CLOCK_GETTIME)
                    set(CLOCK_GETTIME_LINK "-lrt")
            else()
                    # might also be in libc
                    check_library_exists(c clock_gettime "" HAVE_CLOCK_GETTIME)
            endif()

            # Test whether the compiler supports the -pthread option
            set(CMAKE_THREAD_PREFER_PTHREAD ON)
            set(THREADS_PREFER_PTHREAD_FLAG ON)
            find_package(Threads)
            if(CMAKE_USE_PTHREADS_INIT)
                set(HAVE_PTHREAD 1)
            endif()
        endif()
    endif()
else()
    set(BACKTRACE_SUPPORTED 0)
endif()

# Generate backtrace-supported.h and config.h
# backtrace-supported.h.in has syntax which works with CMake out of the box so
# let's not duplicate things unnecessarily.
# config.h.in ain't parsed properly so we need slightly different version.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/backtrace-supported.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/backtrace-supported.h
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
)

# Build commands
add_library(backtrace ${sources} ${FORMAT_FILE} ${VIEW_FILE} ${ALLOC_FILE} ${export_headers})
include_directories(backtrace ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(backtrace ${CLOCK_GETTIME_LINK})
if(CMAKE_USE_PTHREADS_INIT)
    target_link_libraries(backtrace ${CMAKE_THREAD_LIBS_INIT})
endif()
if(ZLIB_FOUND)
    target_link_libraries(backtrace z)
endif()

#install libbacktrace and header files
set(INSTALL_LIB_DIR lib/libbacktrace)
set(INSTALL_INCLUDE_DIR include/libbacktrace)
set(INSTALL_CMAKE_DIR CMake)

# Install CMake files
install(TARGETS backtrace
    DESTINATION ${INSTALL_LIB_DIR}
    EXPORT libbacktrace-targets
)
install(EXPORT libbacktrace-targets DESTINATION ${INSTALL_CMAKE_DIR})
install(FILES
    ${CMAKE_SOURCE_DIR}/cmake/libbacktraceConfig.cmake
    ${CMAKE_SOURCE_DIR}/cmake/libbacktraceConfigVersion.cmake
    DESTINATION ${INSTALL_CMAKE_DIR}
)

install(TARGETS backtrace DESTINATION "${INSTALL_LIB_DIR}")
install(FILES ${export_headers} DESTINATION "${INSTALL_INCLUDE_DIR}")
