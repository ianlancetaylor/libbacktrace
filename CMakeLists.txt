cmake_minimum_required(VERSION 3.5)

project(backtrace)

# Automake uses -frandom-seed initialized with file name of given file
# but AFAIK it can't be done on CMake, so here's always same seed
set(CMAKE_CXX_FLAGS "-DHAVE_CONFIG_H -funwind-tables -frandom-seed=mySeed -W -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wmissing-format-attribute -Wcast-qual -g -O2")
set(CMAKE_C_FLAGS "-DHAVE_CONFIG_H -funwind-tables -frandom-seed=mySeed -W -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wmissing-format-attribute -Wcast-qual -g -O2")

file(GLOB sources 
	atomic.c dwarf.c fileline.c posix.c print.c sort.c state.c backtrace.c
	simple.c pecoff.c read.c alloc.c config.h
)
file(GLOB export_headers
	${CMAKE_CURRENT_BINARY_DIR}/backtrace.h
	${CMAKE_CURRENT_BINARY_DIR}/backtrace-supported.h
)

add_library(${PROJECT_NAME} ${sources} ${export_headers})
include_directories(${PROJECT_NAME} ${CMAKE_CURRENT_BINARY_DIR})

if(CMAKE_COMPILER_IS_GNUCC)
	set(BACKTRACE_SUPPORTED 1)
	
	# Assume multi-threaded environment
	set(BACKTRACE_SUPPORTS_THREADS 1)

	# Assume ELF/DWARF, meaning that BACKTRACE_SUPPORTS_DATA is hard-coded on.
	set(BACKTRACE_SUPPORTS_DATA 1)
		
	find_package(ZLIB)
	if(ZLIB_FOUND)
		SET(HAVE_LIBZ 1)
		SET(HAVE_ZLIB 1)
		target_link_libraries(${PROJECT_NAME} z)
	else()
		SET(HAVE_LIBZ 0)
		SET(HAVE_ZLIB 0)
	endif()
	
	if(WIN32)
		# Typical MinGW config
		# DWARF2 exception handling could be detected based on parsing gcc --version
		set(BACKTRACE_USES_MALLOC 1)
		SET(BACKTRACE_ELF_SIZE unused)
		SET(BACKTRACE_XCOFF_SIZE unused)
		SET(HAVE_ATOMIC_FUNCTIONS 1)
		SET(HAVE_CLOCK_GETTIME 1)
		SET(HAVE_DECL_STRNLEN 1)
		SET(HAVE_DLFCN_H 0)
		SET(HAVE_DL_ITERATE_PHDR 0)
		SET(HAVE_FCNTL 0)
		SET(HAVE_GETEXECNAME 0)
		SET(HAVE_GETIPINFO 1)
		SET(HAVE_INTTYPES_H 1)
		SET(HAVE_LINK_H 0)
		SET(HAVE_LOADQUERY 0)
		SET(HAVE_LSTAT 0)
		SET(HAVE_MEMORY_H 1)
		SET(HAVE_READLINK 0)
		SET(HAVE_STDINT_H 1)
		SET(HAVE_STDLIB_H 1)
		SET(HAVE_STRINGS_H 1)
		SET(HAVE_STRING_H 1)
		SET(HAVE_SYNC_FUNCTIONS 1)
		SET(HAVE_SYS_LDR_H 0)
		SET(HAVE_SYS_MMAN_H 0)
		SET(HAVE_SYS_STAT_H 1)
		SET(HAVE_SYS_TYPES_H 1)
		SET(HAVE_UNISTD_H 1)
	else()
		set(BACKTRACE_SUPPORTED 0)
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

#install libbacktrace and header files
set(INSTALL_LIB_DIR lib/libbacktrace)
set(INSTALL_INCLUDE_DIR include/libbacktrace)
set(INSTALL_CMAKE_DIR CMake)

# Install CMake files
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${INSTALL_LIB_DIR}
	EXPORT lib${PROJECT_NAME}-targets
)
install(EXPORT lib${PROJECT_NAME}-targets DESTINATION ${INSTALL_CMAKE_DIR})
install(FILES
	${CMAKE_SOURCE_DIR}/cmake/lib${PROJECT_NAME}Config.cmake
	${CMAKE_SOURCE_DIR}/cmake/lib${PROJECT_NAME}ConfigVersion.cmake
	DESTINATION ${INSTALL_CMAKE_DIR}
)

install(TARGETS ${PROJECT_NAME} DESTINATION "${INSTALL_LIB_DIR}")
install(FILES ${export_headers} DESTINATION "${INSTALL_INCLUDE_DIR}")
