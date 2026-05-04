cmake_policy(SET CMP0140 NEW)

set(DUMMY_FILES_DIR "${CMAKE_CURRENT_BINARY_DIR}/DummyFiles")
set(DUMMY_PROG_STEM "dummy_prog")
set(DUMMY_SOURCE_STEM "dummy_source")
set(DUMMY_PROG_NAME "${DUMMY_PROG_STEM}${CMAKE_EXECUTABLE_SUFFIX}")
set(DUMMY_SOURCE_NAME "${DUMMY_SOURCE_STEM}.c")
set(DUMMY_PROG_PATH "${DUMMY_FILES_DIR}/${DUMMY_PROG_NAME}")
set(DUMMY_SOURCE_PATH "${DUMMY_FILES_DIR}/${DUMMY_SOURCE_NAME}")

# include CMake modules
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckCompilerFlag)
include(CheckLibraryExists)
include(CheckLinkerFlag)

function(push_var VARIABLE VALUE)
    if (NOT DEFINED "__var_stack_${VARIABLE}")
        set("__var_stack_${VARIABLE}" "" PARENT_SCOPE)
    endif()
    list(APPEND "__var_stack_${VARIABLE}" ${${VARIABLE}})
    set(${VARIABLE} ${VALUE} PARENT_SCOPE)
endfunction()

function(pop_var VARIABLE)
    list(POP_BACK "__var_stack_${VARIABLE}" TAIL)
    set(${VARIABLE} ${TAIL} PARENT_SCOPE)
endfunction()

function(check_command CMDNAME)
    string(TOUPPER ${CMDNAME} CMDUPPER)
    find_program(${CMDUPPER} ${CMDNAME})
    string(COMPARE NOTEQUAL ${${CMDUPPER}} "${CMDUPPER}-NOTFOUND" "HAVE_${CMDUPPER}")
    return(PROPAGATE ${CMDUPPER} "HAVE_${CMDUPPER}")
endfunction()

function(compile_dummy)
    if (NOT EXISTS ${DUMMY_PROG_PATH})
        try_compile(DUMMY_COMPILE_SUCCESS
            SOURCE_FROM_CONTENT "TryCompileCheck.c"
                "int main(int ac, char* av[]) { return 0; }"
            COPY_FILE ${DUMMY_PROG_PATH}
        )
        if (NOT DUMMY_COMPILE_SUCCESS)
            message(FATAL_ERROR "Cannot compile dummy program, check your environment!")
        endif()
    endif()
endfunction()

function(try_compile_check SHOWNAME VARIABLE SOURCE)
    if(NOT DEFINED ${VARIABLE})
        if(NOT CMAKE_REQUIRED_QUIET)
            message(CHECK_START "Looking for ${SHOWNAME}")
        endif()

        try_compile(COMPILE_SUCCESS
            SOURCE_FROM_VAR "TryCompileCheck.c" SOURCE
        )

        if(${COMPILE_SUCCESS})
            set(${VARIABLE} 1 CACHE INTERNAL "Have ${SHOWNAME}")
            if(NOT CMAKE_REQUIRED_QUIET)
                message(CHECK_PASS "found")
            endif()
        else()
            set(${VARIABLE} "" CACHE INTERNAL "Have ${SHOWNAME}")
            if(NOT CMAKE_REQUIRED_QUIET)
                message(CHECK_FAIL "not found")
            endif()
        endif()
    endif()
endfunction()

function(executable_arch FILEPATH RESULT)
    file(READ ${FILEPATH} EXECUTABLE_PREFIX 0 8 HEX)

    string(REGEX MATCH "^7f454c4601" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "elf32" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^7f454c4602" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "elf64" PARENT_SCOPE)
        return()
    endif()

    # cmake does not support try-compiling an object file
    # here we use DOS header to distinguish PE files
    string(REGEX MATCH "^4d5a" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "pecoff" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^01df" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "xcoff32" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^01f7" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "xcoff64" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^feedface" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "macho32" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^cefaedfe" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "macho32" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^feedfacf" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "macho64" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^cffaedfe" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "macho64" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^cafebabe" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "machofat" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^bebafeca" MATCHED ${EXECUTABLE_PREFIX})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "machofat" PARENT_SCOPE)
        return()
    endif()
endfunction()

function(arch_category ARCHNAME RESULT)
    string(REGEX MATCH "^elf" MATCHED ${PROGRAM_ARCH})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "elf" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^macho" MATCHED ${PROGRAM_ARCH})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "macho" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^pecoff" MATCHED ${PROGRAM_ARCH})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "pecoff" PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCH "^xcoff" MATCHED ${PROGRAM_ARCH})
    if (NOT "${MATCHED}" STREQUAL "")
        set(${RESULT} "xcoff" PARENT_SCOPE)
        return()
    endif()

    if ("${PROGRAM_ARCH}" STREQUAL "unknown")
        set(${RESULT} "unknown" PARENT_SCOPE)
    endif()
endfunction()

function(append_bool_def DEFLIST VARNAME)
    if (DEFINED ARGV2)
        set(DEFNAME ${ARGV2})
    else()
        set(DEFNAME ${VARNAME})
    endif()
    if (${VARNAME})
        list(APPEND ${DEFLIST} "${DEFNAME}=1")
    endif()
    return(PROPAGATE ${DEFLIST})
endfunction()

function(append_value_def DEFLIST VARNAME)
    if (DEFINED ARGV2)
        set(DEFNAME ${ARGV2})
    else()
        set(DEFNAME ${VARNAME})
    endif()
    if (DEFINED ${VARNAME})
        list(APPEND ${DEFLIST} "${DEFNAME}=${${VARNAME}}")
    endif()
    return(PROPAGATE ${DEFLIST})
endfunction()

function(var_to_01 VARNAME)
    if (${VARNAME})
        set(${VARNAME} 1 PARENT_SCOPE)
    else()
        set(${VARNAME} 0 PARENT_SCOPE)
    endif()
endfunction()

function(defs_to_header DEFLIST HDRPATH)
    set(CONTENT "// Generated by CMake\n\n")
    foreach (DEF ${${DEFLIST}})
        string(REPLACE "=" ";" DEFPARTS ${DEF})
        list(LENGTH DEFPARTS NDEFPARTS)
        list(GET DEFPARTS 0 DEFNAME)
        if (${NDEFPARTS} GREATER 1)
            list(GET DEFPARTS 1 DEFVAL)
        endif()
        string(APPEND CONTENT "#define ${DEFNAME} ${DEFVAL}\n")
    endforeach()
    if (EXISTS ${HDRPATH})
        file(READ ${HDRPATH} OLD_CONTENT)
    endif()
    if (NOT OLD_CONTENT STREQUAL CONTENT)
        file(WRITE ${HDRPATH} ${CONTENT})
    endif()
endfunction()

function(add_dummy_target TARGET_NAME)
    if (NOT EXISTS ${DUMMY_SOURCE_PATH})
        file(WRITE ${DUMMY_SOURCE_PATH} "int main(int ac, char* av[]) { return 0; }")
    endif()
    add_executable(${TARGET_NAME} ${DUMMY_SOURCE_PATH})
endfunction()

function(target_add_dsym TARGET_NAME)
    if (NOT HAVE_DSYMUTIL)
        message(FATAL_ERROR "dsymutil unsupported!")
    endif()
    add_custom_target(${TARGET_NAME}_dsym ALL
        COMMAND ${DSYMUTIL} $<TARGET_FILE:${TARGET_NAME}>)
endfunction()

function(add_dwz_of TARGET_NAME)
    if (NOT HAVE_DWZ)
        message(FATAL_ERROR "dwz unsupported!")
    endif()
    add_dummy_target(${TARGET_NAME}_dwz)
    set(DIR $<TARGET_FILE_DIR:${TARGET_NAME}_dwz>)
    set(STEM $<TARGET_FILE_PREFIX:${TARGET_NAME}_dwz>$<TARGET_FILE_BASE_NAME:${TARGET_NAME}_dwz>)
    set(SUFFIX $<TARGET_FILE_SUFFIX:${TARGET_NAME}_dwz>)
    set(DBGINFO ${DIR}/${STEM}_common.debug)
    set(DUMMYFILE ${DIR}/${STEM}_placeholder${SUFFIX})
    set(INPUT $<TARGET_FILE:${TARGET_NAME}>)
    set(OUTPUT $<TARGET_FILE:${TARGET_NAME}_dwz>)
    add_custom_command(
        TARGET ${TARGET_NAME}_dwz POST_BUILD
        DEPENDS ${TARGET_NAME}
        COMMAND ${CMAKE_COMMAND} -E rm -f ${OUTPUT} ${DBGINFO}
        COMMAND ${CMAKE_COMMAND} -E copy ${INPUT} ${OUTPUT}
        COMMAND ${CMAKE_COMMAND} -E copy ${INPUT} ${DUMMYFILE}
        COMMAND ${DWZ} -m ${DBGINFO} ${OUTPUT} ${DUMMYFILE}
        COMMAND ${CMAKE_COMMAND} -E rm -f ${DUMMYFILE}
    )
    set_target_properties(${TARGET_NAME}_dwz PROPERTIES DBGINFO ${DBGINFO})
endfunction()

function(_add_debug_info_of TARGET_NAME SUFFIX FULL BUILD_ID)
    if (NOT HAVE_OBJCOPY_DEBUGLINK)
        message(FATAL_ERROR "debuglink of objcopy unsupported!")
    endif()
    add_dummy_target(${TARGET_NAME}_${SUFFIX})
    add_custom_command(
        TARGET ${TARGET_NAME}_${SUFFIX} POST_BUILD
        DEPENDS ${TARGET_NAME}
        COMMAND ${CMAKE_COMMAND}
            -D READELF=${READELF}
            -D OBJCOPY=${OBJCOPY}
            -D SRC=$<TARGET_FILE:${TARGET_NAME}>
            -D DST=$<TARGET_FILE:${TARGET_NAME}_${SUFFIX}>
            -D FULL=${FULL}
            -D BUILD_ID=${BUILD_ID}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/extract-debuginfo.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endfunction()

function(add_gnu_debuglink_of TARGET_NAME)
    _add_debug_info_of(${TARGET_NAME} gnudebuglink OFF OFF)
endfunction()

function(add_full_gnu_debuglink_of TARGET_NAME)
    _add_debug_info_of(${TARGET_NAME} gnudebuglinkfull ON OFF)
endfunction()

function(add_build_id_of TARGET_NAME)
    _add_debug_info_of(${TARGET_NAME} buildid OFF ON)
endfunction()

function(add_full_build_id_of TARGET_NAME)
    _add_debug_info_of(${TARGET_NAME} buildidfull ON ON)
endfunction()

function(_add_minidebug_of TARGET_NAME SUFFIX V2)
    if (NOT HAVE_MINIDEBUG)
        message(FATAL_ERROR "minidebug unsupported!")
    endif()
    add_dummy_target(${TARGET_NAME}_${SUFFIX})
    add_custom_command(
        TARGET ${TARGET_NAME}_${SUFFIX} POST_BUILD
        DEPENDS ${TARGET_NAME}
        COMMAND ${CMAKE_COMMAND}
            -D READELF=${READELF}
            -D OBJCOPY=${OBJCOPY}
            -D NM=${NM}
            -D XZ=${XZ}
            -D COMM=${COMM}
            -D SRC=$<TARGET_FILE:${TARGET_NAME}>
            -D DST=$<TARGET_FILE:${TARGET_NAME}_${SUFFIX}>
            -D V2=${V2}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/extract-minidebug.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endfunction()

function(add_minidebug_of TARGET_NAME)
    _add_minidebug_of(${TARGET_NAME} minidebug OFF)
endfunction()

function(add_minidebug2_of TARGET_NAME)
    _add_minidebug_of(${TARGET_NAME} minidebug2 ON)
endfunction()
