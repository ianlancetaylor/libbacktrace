/* config.h.cmake */
/* ELF size: 32 or 64 */
#cmakedefine BACKTRACE_ELF_SIZE @BACKTRACE_ELF_SIZE@
/* XCOFF size: 32 or 64 */
#cmakedefine BACKTRACE_XCOFF_SIZE
/* Define to 1 if you have the __atomic functions */
#cmakedefine HAVE_ATOMIC_FUNCTIONS 1
/* Define to 1 if you have the `clock_gettime' function. */
#cmakedefine HAVE_CLOCK_GETTIME 1
/* Define to 1 if you have the declaration of `strnlen', and to 0 if you
   don't. */
#cmakedefine HAVE_DECL_STRNLEN 1
/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine HAVE_DLFCN_H 1
/* Define if dl_iterate_phdr is available. */
#cmakedefine HAVE_DL_ITERATE_PHDR 1
/* Define to 1 if you have the fcntl function */
#cmakedefine HAVE_FCNTL 1
/* Define if getexecname is available. */
#cmakedefine HAVE_GETEXECNAME 1
/* Define if _Unwind_GetIPInfo is available. */
#cmakedefine HAVE_GETIPINFO 1
/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine HAVE_INTTYPES_H 1
/* Define to 1 if you have the `z' library (-lz). */
#cmakedefine HAVE_LIBZ 1
/* Define to 1 if you have the <link.h> header file. */
#cmakedefine HAVE_LINK_H 1
/* Define if AIX loadquery is available. */
#cmakedefine HAVE_LOADQUERY 1
/* Define to 1 if you have the `lstat' function. */
#cmakedefine HAVE_LSTAT 1
/* Define to 1 if you have the <memory.h> header file. */
#cmakedefine HAVE_MEMORY_H 1
/* Define to 1 if you have the `readlink' function. */
#cmakedefine HAVE_READLINK 1
/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H 1
/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine HAVE_STDLIB_H 1
/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H 1
/* Define to 1 if you have the <string.h> header file. */
#cmakedefine HAVE_STRING_H 1
/* Define to 1 if you have the __sync functions */
#cmakedefine HAVE_SYNC_FUNCTIONS 1
/* Define to 1 if you have the <sys/ldr.h> header file. */
#cmakedefine HAVE_SYS_LDR_H 1
/* Define to 1 if you have the <sys/mman.h> header file. */
#cmakedefine HAVE_SYS_MMAN_H 1
/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H 1
/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H 1
/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H 1
/* Define if -lz is available. */
#cmakedefine HAVE_ZLIB 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
#cmakedefine _ALL_SOURCE
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#cmakedefine _GNU_SOURCE
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
#cmakedefine _POSIX_PTHREAD_SEMANTICS
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
#cmakedefine _TANDEM_SOURCE
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
#cmakedefine __EXTENSIONS__
#endif
