cmake_minimum_required(VERSION 3.12)

project(libbacktrace LANGUAGES C VERSION 1.0.0)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()

include(Utils.cmake)
include(CMakePackageConfigHelpers)

# make git ignore binary dir
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/.gitignore "*")


# options
option(ENABLE_DARWIN_AT_RPATH "")
option(DISABLE_WERROR "disable building with -Werror")
option(ENABLE_MULTILIB "enable multilib option")
set(RANDOM_SEED_STRING "libbacktrace" CACHE STRING "custom random seed")
set(BACKTRACE_SRC_RELATIVE "" CACHE STRING "position of libbacktrace source directory")


# global variables
set(EXTRA_FLAGS "")
set(WARNING_FLAGS "")
set(BACKTRACE_SUPPORTED TRUE)
set(BACKTRACE_FILES "")
set(BACKTRACE_FLAGS "")
set(BACKTRACE_DEFINITIONS "")
set(BACKTRACE_PUBLIC_HEADERS "")
set(BACKTRACE_TEST_FLAGS "")
set(BACKTRACE_TEST_LINKS "")


set(GENERATED_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/GeneratedSources")
set(GENERATED_SCRIPTS "${CMAKE_CURRENT_BINARY_DIR}/GeneratedScripts")
set(GENERATED_CONFIGS "${CMAKE_CURRENT_BINARY_DIR}/GeneratedConfigs")


# I am not good at Autotools so I don't know where these definitions come from.
# If you know how to control them, replace logic here.
set(AUTODEFS
    STDC_HEADERS
    _ALL_SOURCE
    _GNU_SOURCE
    _POSIX_PTHREAD_SEMANTICS
    _TANDEM_SOURCE
    __EXTENSIONS__
    _DARWIN_USE_64_BIT_INODE
)
foreach(AUTODEF ${AUTODEFS})
    set(${AUTODEF} 1)
    append_bool_def(BACKTRACE_DEFINITIONS ${AUTODEF})
    add_definitions(-D${AUTODEF}=1)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D${AUTODEF}=1)
endforeach()

# let MSVC shut up safety nonsense
set(_CRT_SECURE_NO_WARNINGS 1)
append_bool_def(BACKTRACE_DEFINITIONS _CRT_SECURE_NO_WARNINGS)

# check for libraries
check_library_exists("z" "compress" "" HAVE_ZLIB)
check_library_exists("zstd" "ZSTD_compress" "" HAVE_ZSTD)
check_library_exists("lzma" "lzma_auto_decoder" "" HAVE_LIBLZMA)


# check for commands
check_command(dwz)
check_command(objcopy)
check_command(readelf)
check_command(dsymutil)
check_command(nm)
check_command(xz)
check_command(comm)

if (HAVE_OBJCOPY)
    execute_process(COMMAND ${OBJCOPY} "--help" OUTPUT_VARIABLE OBJCOPY_HELP)
    string(REGEX MATCH "add-gnu-debuglink" HAVE_OBJCOPY_DEBUGLINK ${OBJCOPY_HELP})
    if (NOT "${HAVE_OBJCOPY_DEBUGLINK}" STREQUAL "")
        set(HAVE_OBJCOPY_DEBUGLINK TRUE)
    endif()
endif()


# check for compiler options
check_compiler_flag(C "-funwind-tables" HAVE_F_UNWIND_TABLES)
check_compiler_flag(C "-frandom-seed=${RANDOM_SEED_STRING}" HAVE_F_RANDOM_SEED)
check_compiler_flag(C "-pthread" HAVE_PTHREAD)
check_compiler_flag(C "-gdwarf-5" HAVE_DWARF5)
if (MSVC)
    # somehow linker check will always pass, skip that for MSVC
    set(HAVE_BUILDID 0)
    set(HAVE_COMPRESSED_DEBUG_ZLIB_GNU 0)
    set(HAVE_COMPRESSED_DEBUG_ZLIB_GABI 0)
    set(HAVE_COMPRESSED_DEBUG_ZSTD 0)
else()
    check_linker_flag(C "-Wl,--build-id" HAVE_BUILDID)
    check_linker_flag(C "-Wl,--compress-debug-sections=zlib-gnu" HAVE_COMPRESSED_DEBUG_ZLIB_GNU)
    check_linker_flag(C "-Wl,--compress-debug-sections=zlib-gabi" HAVE_COMPRESSED_DEBUG_ZLIB_GABI)
    check_linker_flag(C "-Wl,--compress-debug-sections=zst" HAVE_COMPRESSED_DEBUG_ZSTD)
endif()


# check for headers and functions
try_compile_check("sync builtins" HAVE_SYNC_BUILTINS "
    int main(int ac, char* av[]) {
        int i;
        __sync_bool_compare_and_swap(&i, i, i);
        __sync_lock_test_and_set(&i, 1);
        __sync_lock_release(&i);
        return 0;
    }
")
try_compile_check("atomic builtins" HAVE_ATOMIC_BUILTINS "
    int main(int ac, char* av[]) {
        int i;
        __atomic_load_n(&i, __ATOMIC_ACQUIRE);
        __atomic_store_n(&i, 1, __ATOMIC_RELEASE);
        return 0;
    }
")

# check for KERN_PROC and KERN_PROC_PATHNAME in <sys/sysctl.h>
try_compile_check("KERN_PROC" HAVE_KERN_PROC "
    #include <sys/types.h>
    #include <sys/sysctl.h>
    int main(int ac, char* av[]) {
        int mib0 = CTL_KERN;
        int mib1 = KERN_PROC;
        int mib2 = KERN_PROC_PATHNAME;
    }
")
# check for KERN_PROCARGS and KERN_PROC_PATHNAME in <sys/sysctl.h>
try_compile_check("KERN_PROCARGS" HAVE_KERN_PROCARGS "
    #include <sys/types.h>
    #include <sys/sysctl.h>
    int main(int ac, char* av[]) {
        int mib0 = CTL_KERN;
        int mib1 = KERN_PROC_ARGS;
        int mib2 = KERN_PROC_PATHNAME;
    }
")

check_include_file("unwind.h" HAVE_UNWIND_H)
if (HAVE_UNWIND_H)
    push_var(CMAKE_REQUIRED_FLAGS "-Werror-implicit-function-declaration")
    check_symbol_exists("_Unwind_Backtrace" "unwind.h" HAVE_UNWIND_BACKTRACE)
    check_symbol_exists("_Unwind_GetIPInfo" "unwind.h" HAVE_UNWIND_GETIPINFO)
    pop_var(CMAKE_REQUIRED_FLAGS)
endif()

check_include_file("sys/mman.h" HAVE_SYS_MMAN_H)
if (HAVE_SYS_MMAN_H)
    push_var(CMAKE_REQUIRED_FLAGS "-Werror-implicit-function-declaration")
    check_symbol_exists("mmap" "sys/mman.h" HAVE_MMAP)
    check_symbol_exists("MAP_ANONYMOUS" "sys/mman.h" HAVE_MAP_ANON)
    pop_var(CMAKE_REQUIRED_FLAGS)
endif()

check_include_file("link.h" HAVE_LINK_H)
check_include_file("sys/link.h" HAVE_SYS_LINK_H)
if (HAVE_LINK_H OR HAVE_SYS_LINK_H)
    set(HAVE_ELF_LINK_H TRUE)
    if (${HAVE_LINK_H})
        set(ELF_LINK_H "link.h")
    else()
        set(ELF_LINK_H "sys/link.h")
    endif()
    check_symbol_exists("dl_iterate_phdr" ${ELF_LINK_H} HAVE_DL_ITERATE_PHDR)
endif()

check_include_file("mach-o/dyld.h" HAVE_MACH_O_DYLD_H)

check_include_file("sys/ldr.h" HAVE_SYS_LDR_H)
if (HAVE_SYS_LDR_H)
    check_symbol_exists("loadquery" "sys/ldr.h" HAVE_LOADQUERY)
endif()

check_include_file("windows.h" HAVE_WINDOWS_H)
if (HAVE_WINDOWS_H)
    try_compile_check("tlhelp32.h" HAVE_TLHELP32_H "
        #include <windows.h>
        #include <tlhelp32.h>
        int main(int ac, char* av[]) { return 0; }
    ")
endif()
check_symbol_exists("_pgmptr" "stdlib.h" HAVE_PGMPTR)

check_function_exists("strnlen" HAVE_STRNLEN)
check_function_exists("fcntl" HAVE_FCNTL)
check_function_exists("lstat" HAVE_LSTAT)
check_function_exists("readlink" HAVE_READLINK)
check_function_exists("getpagesize" HAVE_GETPAGESIZE)
check_function_exists("getexecname" HAVE_GETEXECNAME)

check_function_exists("clock_gettime" HAVE_CLOCK_GETTIME)
# At least for glibc, clock_gettime is in librt.  But don't
# pull that in if it still doesn't give us the function we want.
if (NOT HAVE_CLOCK_GETTIME)
    unset(HAVE_CLOCK_GETTIME CACHE)
    check_library_exists("rt" "clock_gettime" "" HAVE_CLOCK_GETTIME)
    if (HAVE_CLOCK_GETTIME)
        set(CLOCK_GETTIME_IN_LIBRT TRUE CACHE INTERNAL "clock_gettime is from librt")
    endif()
endif()


if (NOT MSVC)
    # set warning flags
    list(APPEND WARNING_FLAGS
        -W -Wall -Wwrite-strings -Wstrict-prototypes
        -Wmissing-prototypes -Wold-style-definition
        -Wmissing-format-attribute -Wcast-qual
        -Wno-attributes -Wno-unknown-attributes
        -Wpointer-arith
    )
    if (NOT DISABLE_WERROR)
        list(APPEND WARNING_FLAGS -Werror)
    endif()
endif()

# common source files
list(APPEND BACKTRACE_FILES atomic.c dwarf.c fileline.c posix.c print.c sort.c state.c)

# configure according to conditions
if (ENABLE_MULTILIB)
    list(APPEND BACKTRACE_FLAGS "--enable-multilib")
endif()

if (HAVE_F_UNWIND_TABLES)
    list(APPEND EXTRA_FLAGS "-funwind-tables")
endif()
if (HAVE_F_RANDOM_SEED)
    list(APPEND EXTRA_FLAGS "-frandom-seed=${RANDOM_SEED_STRING}")
endif()
if (HAVE_PTHREAD)
    list(APPEND BACKTRACE_TEST_FLAGS "-pthread")
endif()

if (CLOCK_GETTIME_IN_LIBRT)
    list(APPEND BACKTRACE_TEST_LINKS "rt")
endif()

if (HAVE_UNWIND_H AND HAVE_UNWIND_BACKTRACE)
    list(APPEND BACKTRACE_FILES backtrace.c simple.c)
else()
    list(APPEND BACKTRACE_FILES nounwind.c)
    unset(BACKTRACE_SUPPORTED)
endif()

if (HAVE_SYNC_BUILTINS)
    set(BACKTRACE_SUPPORTS_THREADS TRUE)
endif()

set(SYS_IOMEM_FILES "")
if (HAVE_SYS_MMAN_H AND HAVE_MMAP)
    list(APPEND SYS_IOMEM_FILES mmapio.c)
    if (${HAVE_MAP_ANON})
        list(APPEND SYS_IOMEM_FILES mmap.c)
    else()
        list(APPEND SYS_IOMEM_FILES alloc.c)
        set(BACKTRACE_USES_MALLOC TRUE)
    endif()
else()
    list(APPEND SYS_IOMEM_FILES read.c alloc.c)
    set(BACKTRACE_USES_MALLOC TRUE)
endif()


# check dummy executable to know build target type
if(NOT DEFINED PROGRAM_ARCH)
    message(CHECK_START "Checking target program architecture")
    compile_dummy()
    executable_arch(${DUMMY_PROG_PATH} PROGRAM_ARCH)
    if (DEFINED PROGRAM_ARCH)
        message(CHECK_PASS ${PROGRAM_ARCH})
    else()
        message(CHECK_FAIL "unknown format")
        set(PROGRAM_ARCH "unknown")
    endif()
    set(PROGRAM_ARCH ${PROGRAM_ARCH} CACHE INTERNAL "local program architecture")
endif()
arch_category(${PROGRAM_ARCH} TARGET_TYPE)
message(STATUS "Build target is ${TARGET_TYPE}")

# set implementation specific attributes
set(BACKTRACE_SUPPORTS_DATA TRUE)
if ("${TARGET_TYPE}" STREQUAL "unknown")
    # unknown format
    unset(BACKTRACE_SUPPORTED)
elseif ("${TARGET_TYPE}" STREQUAL "elf")
    # elf specific
    set(HAVE_ELF TRUE)
    if (HAVE_OBJCOPY AND HAVE_NM AND HAVE_XZ AND HAVE_COMM)
        set(HAVE_MINIDEBUG TRUE)
    endif()
elseif ("${TARGET_TYPE}" STREQUAL "xcoff")
    # xcoff specific
    unset(BACKTRACE_SUPPORTS_DATA)
elseif ("${TARGET_TYPE}" STREQUAL "macho")
    # macho specific
    if (HAVE_DSYMUTIL)
        set(USE_DYMUTIL ON)
    endif()
elseif ("${TARGET_TYPE}" STREQUAL "pecoff")
    # pecoff specific
    unset(BACKTRACE_SUPPORTS_DATA)
endif()


# implicit definitions created by AC_CHECK_DECLS
append_bool_def(BACKTRACE_DEFINITIONS HAVE_PGMPTR HAVE_DECL__PGMPTR)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_GETPAGESIZE HAVE_DECL_GETPAGESIZE)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_STRNLEN HAVE_DECL_STRNLEN)

# implicit definitions created by AC_CHECK_HEADERS
append_bool_def(BACKTRACE_DEFINITIONS HAVE_SYS_MMAN_H)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_LINK_H)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_SYS_LINK_H)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_MACH_O_DYLD_H)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_SYS_LDR_H)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_WINDOWS_H)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_TLHELP32_H)

# explicit definitions registered with AC_DEFINE
append_bool_def(BACKTRACE_DEFINITIONS HAVE_UNWIND_GETIPINFO HAVE_GETIPINFO)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_SYNC_BUILTINS HAVE_SYNC_FUNCTIONS)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_ATOMIC_BUILTINS HAVE_ATOMIC_FUNCTIONS)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_DL_ITERATE_PHDR)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_LOADQUERY)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_FCNTL)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_LSTAT)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_READLINK)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_GETEXECNAME)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_KERN_PROC)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_KERN_PROCARGS HAVE_KERN_PROC_ARGS)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_CLOCK_GETTIME)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_ZLIB)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_ZSTD)
append_bool_def(BACKTRACE_DEFINITIONS HAVE_LIBLZMA)

# dump definitions to config.h
defs_to_header(BACKTRACE_DEFINITIONS ${GENERATED_SOURCES}/config.h)

# convert needed vars to 0/1
var_to_01(BACKTRACE_SUPPORTED)
var_to_01(BACKTRACE_USES_MALLOC)
var_to_01(BACKTRACE_SUPPORTS_THREADS)
var_to_01(BACKTRACE_SUPPORTS_DATA)

# format backtrace-supported.h
configure_file(backtrace-supported.h.in ${GENERATED_SOURCES}/backtrace-supported.h)

# fix unistd.h problem for MSVC
if (MSVC)
    if (NOT EXISTS ${GENERATED_SOURCES}/unistd.h)
        file(WRITE ${GENERATED_SOURCES}/unistd.h "
            #include <io.h>
            #include <basetsd.h>
            #include <process.h>
            typedef SSIZE_T ssize_t;
        ")
    endif()
endif()


function(add_backtrace_part TARGET_NAME)
    cmake_parse_arguments(PARSE_ARGV 1 PART "" "" "SRCS;DEFS;FLAGS")
    add_library(${TARGET_NAME} OBJECT EXCLUDE_FROM_ALL ${PART_SRCS})
    target_compile_options(${TARGET_NAME} PRIVATE ${BACKTRACE_FLAGS} ${WARNING_FLAGS} ${EXTRA_FLAGS} ${PART_FLAGS})
    target_include_directories(${TARGET_NAME} PUBLIC . ${GENERATED_SOURCES})
    if (DEFINED PART_DEFS)
        target_compile_definitions(${TARGET_NAME} PRIVATE ${PART_DEFS})
    endif()
endfunction()

function(add_backtrace_part_with_pic TARGET_NAME)
    list(SUBLIST ARGV 1 -1 OPTARGS)
    add_backtrace_part(${TARGET_NAME} ${OPTARGS})
    if (MSVC)
        # MSVC have no PIC option and Windows DLL doesn't need to be PIC 
        add_library(${TARGET_NAME}_pic ALIAS ${TARGET_NAME})
    else()
        add_backtrace_part(${TARGET_NAME}_pic ${OPTARGS} FLAGS -fPIC)
    endif()
endfunction()

add_backtrace_part_with_pic(common SRCS ${BACKTRACE_FILES})

add_backtrace_part_with_pic(fmt_unknown SRCS unknown.c)
add_backtrace_part_with_pic(fmt_elf32 SRCS elf.c DEFS BACKTRACE_ELF_SIZE=32)
add_backtrace_part_with_pic(fmt_elf64 SRCS elf.c DEFS BACKTRACE_ELF_SIZE=64)
add_backtrace_part_with_pic(fmt_xcoff32 SRCS xcoff.c DEFS BACKTRACE_XCOFF_SIZE=32)
add_backtrace_part_with_pic(fmt_xcoff64 SRCS xcoff.c DEFS BACKTRACE_XCOFF_SIZE=64)
add_backtrace_part_with_pic(fmt_macho SRCS macho.c)
add_backtrace_part_with_pic(fmt_pecoff SRCS pecoff.c)

add_backtrace_part_with_pic(iomem_sys SRCS ${SYS_IOMEM_FILES})
add_backtrace_part(iomem_generic SRCS read.c alloc.c)
add_backtrace_part(iomem_instrumented SRCS read.c instrumented_alloc.c)


# Finally, hello, libbacktrace!
add_library(backtrace SHARED)
target_link_libraries(backtrace PRIVATE
    $<BUILD_INTERFACE:common_pic fmt_${PROGRAM_ARCH}_pic iomem_sys_pic>
)
target_include_directories(backtrace PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR} ${GENERATED_SOURCES}>  
    $<INSTALL_INTERFACE:include>
)

add_library(backtrace_a STATIC)
target_link_libraries(backtrace_a PRIVATE
    $<BUILD_INTERFACE:common fmt_${PROGRAM_ARCH} iomem_sys>
)
target_include_directories(backtrace_a PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR} ${GENERATED_SOURCES}>  
    $<INSTALL_INTERFACE:include>
)


configure_package_config_file(
    libbacktrace-config.cmake.in
    ${GENERATED_CONFIGS}/libbacktrace-config.cmake
    INSTALL_DESTINATION CMake
)
write_basic_package_version_file(
    ${GENERATED_CONFIGS}/libbacktrace-version.cmake
    VERSION ${libbacktrace_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(
    FILES backtrace.h ${GENERATED_SOURCES}/backtrace-supported.h
    DESTINATION include
)
install(
    TARGETS backtrace backtrace_a
    DESTINATION lib
    EXPORT libbacktrace-targets
)
install(
    EXPORT libbacktrace-targets
    DESTINATION CMake
)
install(
    FILES ${GENERATED_CONFIGS}/libbacktrace-config.cmake
          ${GENERATED_CONFIGS}/libbacktrace-version.cmake
    DESTINATION CMake
)


# tests here ...
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING AND BACKTRACE_SUPPORTED)
    function(add_backtrace_test TARGET_NAME)
        cmake_parse_arguments(PARSE_ARGV 1 TEST
            "WRAPPED;DSYM" "CWD" "SRCS;DEFS;PARTS;LINKS;COMMAND;FLAGS;LDFLAGS;DEPFILE")
        if (NOT DEFINED TEST_PARTS)
            set(TEST_PARTS common fmt_${PROGRAM_ARCH} iomem_sys)
        endif()
        if (NOT DEFINED TEST_COMMAND)
            set(TEST_COMMAND ${TARGET_NAME})
        endif()
        if (TEST_WRAPPED)
            list(APPEND TEST_DEPFILE ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}${SCRIPT_SUFFIX})
            set(TEST_COMMAND ${INTERPRETER} $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}${SCRIPT_SUFFIX})
        endif()
        if (NOT DEFINED TEST_CWD)
            set(TEST_CWD $<TARGET_FILE_DIR:${TARGET_NAME}>)
        endif()
        add_executable(${TARGET_NAME} ${TEST_SRCS})
        set(ALL_LINKS ${TEST_PARTS} ${BACKTRACE_TEST_LINKS} ${TEST_LINKS})
        set(ALL_DEFS ${TEST_DEFS})
        set(ALL_FLAGS ${BACKTRACE_TEST_FLAGS} ${EXTRA_FLAGS} -g ${TEST_FLAGS})
        set(ALL_LDFLAGS ${TEST_LDFLAGS} -g)
        if (NOT "${ALL_LINKS}" STREQUAL "")
            target_link_libraries(${TARGET_NAME} PRIVATE ${ALL_LINKS})
        endif()
        if (NOT "${ALL_DEFS}" STREQUAL "")
            target_compile_definitions(${TARGET_NAME} PRIVATE ${ALL_DEFS})
        endif()
        if (NOT "${ALL_FLAGS}" STREQUAL "")
            target_compile_options(${TARGET_NAME} PRIVATE ${ALL_FLAGS})
        endif()
        if (NOT "${ALL_LDFLAGS}" STREQUAL "")
            target_link_options(${TARGET_NAME} PRIVATE ${ALL_LDFLAGS})
        endif()
        add_test(NAME ${TARGET_NAME}
            COMMAND ${TEST_COMMAND}
            WORKING_DIRECTORY ${TEST_CWD})
        foreach (FPATH ${TEST_DEPFILE})
            get_filename_component(FNAME ${FPATH} NAME)
            add_custom_command(
                TARGET ${TARGET_NAME} POST_BUILD
                DEPENDS ${FPATH}
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${FPATH} $<TARGET_FILE_DIR:${TARGET_NAME}>/${FNAME}
            )
        endforeach()
        if (TEST_DSYM AND HAVE_DSYMUTIL)
            target_add_dsym(${TARGET_NAME})
        endif()
    endfunction()

    set(ALLOC_PARTS common fmt_${PROGRAM_ARCH} iomem_generic)

    function(add_backtrace_test_with_alloc TARGET_NAME)
        list(SUBLIST ARGV 1 -1 OPTARGS)
        add_backtrace_test(${TARGET_NAME} ${OPTARGS})
        add_backtrace_test(${TARGET_NAME}_alloc ${OPTARGS} PARTS ${ALLOC_PARTS})
    endfunction()

    function(add_buildid_test NAME)
        set(SCRIPT_WRAPPER ${GENERATED_SCRIPTS}/${NAME}.sh)
        configure_file(run-debuginfo-test.sh.in ${SCRIPT_WRAPPER})
        add_custom_command(
            TARGET ${NAME} POST_BUILD
            DEPENDS ${SCRIPT_WRAPPER}
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${SCRIPT_WRAPPER} $<TARGET_FILE_DIR:${NAME}>/${NAME}.sh
        )
        add_test(NAME ${NAME} COMMAND sh $<TARGET_FILE_DIR:${NAME}>/${NAME}.sh)
    endfunction()

    function(add_debug_info_test_of TARGET_NAME)
        cmake_parse_arguments(PARSE_ARGV 1 TEST
            "DWZ;GNU_DEBUGLINK;FULL_GNU_DEBUGLINK;BUILD_ID;FULL_BUILD_ID;MINIDEBUG;MINIDEBUG2" "" "")
        if (HAVE_DWZ AND TEST_DWZ)
            add_dwz_of(${TARGET_NAME})
            add_test(NAME ${TARGET_NAME}_dwz COMMAND ${TARGET_NAME}_dwz)
        endif()
        if (HAVE_OBJCOPY_DEBUGLINK AND NOT WIN32) # do not test on win32
            if (TEST_GNU_DEBUGLINK)
                add_gnu_debuglink_of(${TARGET_NAME})
                add_test(NAME ${TARGET_NAME}_gnudebuglink COMMAND ${TARGET_NAME}_gnudebuglink)
            endif()
            if (TEST_FULL_GNU_DEBUGLINK)
                add_full_gnu_debuglink_of(${TARGET_NAME})
                add_test(NAME ${TARGET_NAME}_gnudebuglinkfull COMMAND ${TARGET_NAME}_gnudebuglinkfull)
            endif()
            if (TEST_BUILD_ID)
                add_build_id_of(${TARGET_NAME})
                add_buildid_test(${TARGET_NAME}_buildid)
            endif()
            if (TEST_FULL_BUILD_ID)
                add_full_build_id_of(${TARGET_NAME})
                add_buildid_test(${TARGET_NAME}_buildidfull)
            endif()
        endif()
        if (HAVE_MINIDEBUG)
            if (TEST_MINIDEBUG)
                add_minidebug_of(${TARGET_NAME})
                add_test(NAME ${TARGET_NAME}_minidebug COMMAND ${TARGET_NAME}_minidebug)
            endif()
            if (TEST_MINIDEBUG2)
                add_minidebug2_of(${TARGET_NAME})
                add_buildid_test(${TARGET_NAME}_minidebug2)
            endif()
        endif()
    endfunction()

    if (WIN32)
        set(SCRIPT_SUFFIX ".ps1")
        set(INTERPRETER powershell -File)
    else()
        set(SCRIPT_SUFFIX ".sh")
        set(INTERPRETER sh)
    endif()

    foreach (FORMAT unknown elf32 elf64 xcoff32 xcoff64 macho pecoff)
        add_backtrace_test(test_${FORMAT}
            SRCS test_format.c testlib.c
            PARTS common fmt_${FORMAT} iomem_sys
        )
    endforeach()

    add_backtrace_test_with_alloc(unittest
        SRCS unittest.c testlib.c
    )

    add_backtrace_test(allocfail WRAPPED DSYM
        SRCS allocfail.c testlib.c
        PARTS common fmt_${PROGRAM_ARCH} iomem_instrumented
    )

    add_backtrace_test_with_alloc(btest DSYM
        SRCS btest.c testlib.c
        FLAGS -O
    )
    add_debug_info_test_of(btest GNU_DEBUGLINK FULL_GNU_DEBUGLINK)
    if (HAVE_DWZ)
        add_dwz_of(btest)
        add_debug_info_test_of(btest_dwz GNU_DEBUGLINK)
    endif()
    if (HAVE_ELF)
        add_backtrace_test(btest_lto
            SRCS btest.c testlib.c
            FLAGS -O -flto
        )
        if (HAVE_BUILDID AND HAVE_OBJCOPY_DEBUGLINK)
            add_backtrace_test(b2test
                SRCS btest.c testlib.c
                LDFLAGS -Wl,--build-id
            )
            add_debug_info_test_of(b2test BUILD_ID FULL_BUILD_ID)
            if (HAVE_DWZ)
                add_backtrace_test(b3test
                    SRCS btest.c testlib.c
                    LDFLAGS -Wl,--build-id
                )
                add_dwz_of(b3test)
                add_debug_info_test_of(b3test_dwz BUILD_ID FULL_BUILD_ID)
            endif()
        endif()
    endif()

    add_backtrace_test_with_alloc(stest DSYM
        SRCS stest.c
    )

    if (HAVE_ELF)
        if (HAVE_ZLIB)
            set(ZLIB_LINK z)
        endif()
        if (HAVE_ZSTD)
            set(ZSTD_LINK zstd)
        endif()
        if (HAVE_LZMA)
            set(LZMA_LINK lzma)
        endif()
        add_backtrace_test_with_alloc(ztest
            SRCS ztest.c testlib.c
            DEFS "SRCDIR=\"${CMAKE_CURRENT_SOURCE_DIR}\""
            LINKS ${ZLIB_LINK}
        )
        add_backtrace_test_with_alloc(zstdtest
            SRCS zstdtest.c testlib.c
            DEFS "SRCDIR=\"${CMAKE_CURRENT_SOURCE_DIR}\""
            LINKS ${ZSTD_LINK}
        )
        add_backtrace_test_with_alloc(xztest
            SRCS xztest.c testlib.c
            DEFS "SRCDIR=\"${CMAKE_CURRENT_SOURCE_DIR}\""
            LINKS ${LZMA_LINK}
        )
    endif()

    if (NOT EXISTS ${GENERATED_SOURCES}/edtest2_build.c)
        file(TOUCH ${GENERATED_SOURCES}/edtest2_build.c)
    endif()
    add_custom_target(edtest_build
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/edtest2.c ${GENERATED_SOURCES}/edtest2_build.c
    )
    add_backtrace_test_with_alloc(edtest DSYM
        SRCS edtest.c ${GENERATED_SOURCES}/edtest2_build.c testlib.c
    )
    add_dependencies(edtest edtest_build)
    add_dependencies(edtest_alloc edtest_build)

    add_backtrace_test_with_alloc(ttest DSYM
        SRCS ttest.c testlib.c
        LINKS pthread
    )

    if (HAVE_COMPRESSED_DEBUG_ZLIB_GNU)
        add_backtrace_test_with_alloc(ctestg
            SRCS btest.c testlib.c
            LDFLAGS -Wl,--compress-debug-sections=zlib-gnu
        )
    endif()
    if (HAVE_COMPRESSED_DEBUG_ZLIB_GABI)
        add_backtrace_test_with_alloc(ctesta
            SRCS btest.c testlib.c
            LDFLAGS -Wl,--compress-debug-sections=zlib-gabi
        )
    endif()
    if (HAVE_COMPRESSED_DEBUG_ZSTD)
        add_backtrace_test_with_alloc(ctestzstd
            SRCS btest.c testlib.c
            LDFLAGS -Wl,--compress-debug-sections=zstd
        )
    endif()

    add_backtrace_test_with_alloc(dwarf5 DSYM
        SRCS btest.c testlib.c
        FLAGS -gdwarf-5
    )

    add_backtrace_test(mtest DSYM
        SRCS mtest.c testlib.c
        FLAGS -O
    )
    add_debug_info_test_of(mtest MINIDEBUG)
    add_backtrace_test(m2test
        SRCS mtest.c testlib.c
        FLAGS -O
        LDFLAGS -Wl,--build-id
    )
    add_debug_info_test_of(m2test MINIDEBUG2)
endif()
