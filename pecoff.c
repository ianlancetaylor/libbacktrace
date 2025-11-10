/* pecoff.c -- Get debug data from a PE/COFFF file for backtraces.
   Copyright (C) 2015-2024 Free Software Foundation, Inc.
   Adapted from elf.c by Tristan Gingold, AdaCore.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    (1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

    (2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

    (3) The name of the author may not be used to
    endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.  */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "backtrace.h"
#include "internal.h"

#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#ifdef HAVE_TLHELP32_H
#include <tlhelp32.h>

#ifdef UNICODE
/* If UNICODE is defined, all the symbols are replaced by a macro to use the
   wide variant. But we need the ansi variant, so undef the macros. */
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif
#endif

#if defined(_ARM_)
#define NTAPI
#else
#define NTAPI __stdcall
#endif

/* This is a simplified (but binary compatible) version of what Microsoft
   defines in their documentation. */
struct dll_notification_data
{
  ULONG reserved;
  /* The name as UNICODE_STRING struct. */
  PVOID full_dll_name;
  PVOID base_dll_name;
  PVOID dll_base;
  ULONG size_of_image;
};

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

typedef LONG NTSTATUS;
typedef VOID (CALLBACK *LDR_DLL_NOTIFICATION)(ULONG,
					      struct dll_notification_data*,
					      PVOID);
typedef NTSTATUS (NTAPI *LDR_REGISTER_FUNCTION)(ULONG,
						LDR_DLL_NOTIFICATION, PVOID,
						PVOID*);
#endif

/* Coff file header.  */

typedef struct {
  uint16_t machine;
  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_header;
  uint16_t characteristics;
} b_coff_file_header;

/* Coff optional header.  */

typedef struct {
  uint16_t magic;
  uint8_t  major_linker_version;
  uint8_t  minor_linker_version;
  uint32_t size_of_code;
  uint32_t size_of_initialized_data;
  uint32_t size_of_uninitialized_data;
  uint32_t address_of_entry_point;
  uint32_t base_of_code;
  union {
    struct {
      uint32_t base_of_data;
      uint32_t image_base;
    } pe;
    struct {
      uint64_t image_base;
    } pep;
  } u;
} b_coff_optional_header;

/* Values of magic in optional header.  */

#define PE_MAGIC 0x10b		/* PE32 executable.  */
#define PEP_MAGIC 0x20b		/* PE32+ executable (for 64bit targets).  */

/* Coff section header.  */

typedef struct {
  char name[8];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t size_of_raw_data;
  uint32_t pointer_to_raw_data;
  uint32_t pointer_to_relocations;
  uint32_t pointer_to_line_numbers;
  uint16_t number_of_relocations;
  uint16_t number_of_line_numbers;
  uint32_t characteristics;
} b_coff_section_header;

/* Coff symbol name.  */

typedef union {
  char short_name[8];
  struct {
    unsigned char zeroes[4];
    unsigned char off[4];
  } long_name;
} b_coff_name;

/* Coff symbol (external representation which is unaligned).  */

typedef struct {
  b_coff_name name;
  unsigned char value[4];
  unsigned char section_number[2];
  unsigned char type[2];
  unsigned char storage_class;
  unsigned char number_of_aux_symbols;
} b_coff_external_symbol;

/* Symbol types.  */

#define N_TBSHFT 4			/* Shift for the derived type.  */
#define IMAGE_SYM_DTYPE_FUNCTION 2	/* Function derived type.  */

/* Size of a coff symbol.  */

#define SYM_SZ 18

/* Coff symbol, internal representation (aligned).  */

typedef struct {
  const char *name;
  uint32_t value;
  int16_t sec;
  uint16_t type;
  uint16_t sc;
} b_coff_internal_symbol;

/* Names of sections, indexed by enum dwarf_section in internal.h.  */

static const char * const debug_section_names[DEBUG_MAX] =
{
  ".debug_info",
  ".debug_line",
  ".debug_abbrev",
  ".debug_ranges",
  ".debug_str",
  ".debug_addr",
  ".debug_str_offsets",
  ".debug_line_str",
  ".debug_rnglists"
};

/* Information we gather for the sections we care about.  */

struct debug_section_info
{
  /* Section file offset.  */
  off_t offset;
  /* Section size.  */
  size_t size;
};

/* Information we keep for an coff symbol.  */

struct coff_symbol
{
  /* The name of the symbol.  */
  const char *name;
  /* The address of the symbol.  */
  uintptr_t address;
};

/* Information to pass to coff_syminfo.  */

struct coff_syminfo_data
{
  /* Symbols for the next module.  */
  struct coff_syminfo_data *next;
  /* The COFF symbols, sorted by address.  */
  struct coff_symbol *symbols;
  /* The number of symbols.  */
  size_t count;
};

/* A dummy callback function used when we can't find any debug info.  */

static int
coff_nodebug (struct backtrace_state *state ATTRIBUTE_UNUSED,
	      uintptr_t pc ATTRIBUTE_UNUSED,
	      backtrace_full_callback callback ATTRIBUTE_UNUSED,
	      backtrace_error_callback error_callback, void *data)
{
  error_callback (data, "no debug info in PE/COFF executable (make sure to compile with -g)", -1);
  return 0;
}

/* A dummy callback function used when we can't find a symbol
   table.  */

static void
coff_nosyms (struct backtrace_state *state ATTRIBUTE_UNUSED,
	     uintptr_t addr ATTRIBUTE_UNUSED,
	     backtrace_syminfo_callback callback ATTRIBUTE_UNUSED,
	     backtrace_error_callback error_callback, void *data)
{
  error_callback (data, "no symbol table in PE/COFF executable", -1);
}

/* Read a potentially unaligned 4 byte word at P, using native endianness.  */

static uint32_t
coff_read4 (const unsigned char *p)
{
  uint32_t res;

  memcpy (&res, p, 4);
  return res;
}

/* Compute the CRC-32 of BUF/LEN.  This uses the CRC used for
   .gnu_debuglink files.  */

static uint32_t
coff_crc32 (uint32_t crc, const unsigned char *buf, size_t len)
{
  static const uint32_t crc32_table[256] =
    {
      0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
      0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
      0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
      0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
      0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
      0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
      0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
      0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
      0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
      0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
      0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
      0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
      0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
      0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
      0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
      0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
      0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
      0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
      0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
      0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
      0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
      0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
      0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
      0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
      0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
      0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
      0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
      0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
      0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
      0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
      0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
      0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
      0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
      0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
      0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
      0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
      0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
      0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
      0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
      0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
      0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
      0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
      0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
      0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
      0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
      0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
      0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
      0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
      0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
      0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
      0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
      0x2d02ef8d
    };
  const unsigned char *end;

  crc = ~crc;
  for (end = buf + len; buf < end; ++ buf)
    crc = crc32_table[(crc ^ *buf) & 0xff] ^ (crc >> 8);
  return ~crc;
}

/* Return the CRC-32 of the entire file open at DESCRIPTOR.  */

static uint32_t
coff_crc32_file (struct backtrace_state *state, int descriptor,
		  backtrace_error_callback error_callback, void *data)
{
  struct stat st;
  struct backtrace_view file_view;
  uint32_t ret;

  if (fstat (descriptor, &st) < 0)
    {
      error_callback (data, "fstat", errno);
      return 0;
    }

  if (!backtrace_get_view (state, descriptor, 0, st.st_size, error_callback,
			   data, &file_view))
    return 0;

  ret = coff_crc32 (0, (const unsigned char *) file_view.data, st.st_size);

  backtrace_release_view (state, &file_view, error_callback, data);

  return ret;
}

/* Read a potentially unaligned 2 byte word at P, using native endianness.
   All 2 byte word in symbols are always aligned, but for coherency all
   fields are declared as char arrays.  */

static uint16_t
coff_read2 (const unsigned char *p)
{
  uint16_t res;

  memcpy (&res, p, sizeof (res));
  return res;
}

/* Try to open a file whose name is PREFIX (length PREFIX_LEN)
   concatenated with PREFIX2 (length PREFIX2_LEN) concatenated with
   DEBUGLINK_NAME.  Returns an open file descriptor, or -1.  */

static int
coff_try_debugfile (struct backtrace_state *state, const char *prefix,
                    size_t prefix_len, const char *prefix2, size_t prefix2_len,
                    const char *debuglink_name,
                    backtrace_error_callback error_callback, void *data)
{
  size_t debuglink_len;
  size_t try_len;
  char *try;
  int does_not_exist;
  int ret;

  debuglink_len = strlen (debuglink_name);
  try_len = prefix_len + prefix2_len + debuglink_len + 1;
  try = backtrace_alloc (state, try_len, error_callback, data);
  if (try == NULL)
    return -1;

  memcpy (try, prefix, prefix_len);
  memcpy (try + prefix_len, prefix2, prefix2_len);
  memcpy (try + prefix_len + prefix2_len, debuglink_name, debuglink_len);
  try[prefix_len + prefix2_len + debuglink_len] = '\0';

  ret = backtrace_open (try, error_callback, data, &does_not_exist);

  /* If we successfully opened the candidate debug file, show the full
     path so the user can confirm which file was used.  Free 'try' after
     this diagnostic. */

  if (ret >= 0)
    {
  backtrace_free (state, try, try_len, error_callback, data);
    }
  else
    backtrace_free (state, try, try_len, error_callback, data);

  return ret;
}

/* Find a separate debug info file, using the debuglink section data
   to find it.  Returns an open file descriptor, or -1.  */

static int
coff_find_debugfile_by_debuglink (struct backtrace_state *state,
                                  const char *filename,
                                  const char *debuglink_name,
                                  backtrace_error_callback error_callback,
                                  void *data)
{
  int ret;
  char *alc;
  size_t alc_len;
  /* 'slash' was used in older code; directory separator handling is below. */
  int ddescriptor;
  const char *prefix;
  size_t prefix_len;

  ret = -1;
  alc = NULL;
  alc_len = 0;

  /* Look for DEBUGLINK_NAME in the same directory as FILENAME.  */

  {
    const char *last_slash = strrchr (filename, '/');
    const char *last_bslash = strrchr (filename, '\\');
    /* Pick the last directory separator, supporting both Unix and
       Windows-style paths. */
    if (last_slash == NULL && last_bslash == NULL)
      {
        prefix = "";
        prefix_len = 0;
      }
    else
      {
        const char *sep = last_slash;
        if (last_bslash != NULL && (last_slash == NULL || last_bslash > last_slash))
          sep = last_bslash;
        /* Move past the separator for the prefix length. */
        prefix = filename;
        prefix_len = (sep - filename) + 1;
      }
  }

  ddescriptor = coff_try_debugfile (state, prefix, prefix_len, "", 0,
                                    debuglink_name, error_callback, data);
  if (ddescriptor >= 0)
    {
      ret = ddescriptor;
      goto done;
    }

  /* Look for DEBUGLINK_NAME in a .debug subdirectory of FILENAME.  */

#ifndef HAVE_WINDOWS_H
  ddescriptor = coff_try_debugfile (state, prefix, prefix_len, ".debug/",
                                    strlen (".debug/"), debuglink_name,
                                    error_callback, data);
  if (ddescriptor >= 0)
    {
      ret = ddescriptor;
      goto done;
    }

  /* Look for DEBUGLINK_NAME in /usr/lib/debug.  */
  
  ddescriptor = coff_try_debugfile (state, "/usr/lib/debug/",
                                    strlen ("/usr/lib/debug/"), prefix,
                                    prefix_len, debuglink_name,
                                    error_callback, data);

  if (ddescriptor >= 0)
    ret = ddescriptor;
#else
  ddescriptor = coff_try_debugfile (state, prefix, prefix_len, ".debug\\",
                                    strlen (".debug\\"), debuglink_name,
                                    error_callback, data);
  if (ddescriptor >= 0)
    ret = ddescriptor;
#endif

 done:
  if (alc != NULL && alc_len > 0)
    backtrace_free (state, alc, alc_len, error_callback, data);
  return ret;
}

/* Open a separate debug info file, using the debuglink section data
   to find it.  Returns an open file descriptor, or -1.  */

static int
coff_open_debugfile_by_debuglink (struct backtrace_state *state,
                                  const char *filename,
                                  const char *debuglink_name,
                                  uint32_t debuglink_crc,
                                  backtrace_error_callback error_callback,
                                  void *data)
{
  int ddescriptor;

  ddescriptor = coff_find_debugfile_by_debuglink (state, filename,
                                                  debuglink_name,
                                                  error_callback, data);
  if (ddescriptor < 0)
    return -1;

  if (debuglink_crc != 0)
    {
      uint32_t got_crc;

      got_crc = coff_crc32_file (state, ddescriptor, error_callback, data);
      if (got_crc != debuglink_crc)
        {
          {
            char _msg[256];
            snprintf (_msg, sizeof (_msg), "CRC mismatch for %s: got 0x%08x expected 0x%08x",
                      filename ? filename : "(unknown)", got_crc, debuglink_crc);
            error_callback (data, _msg, 0);
          }
          backtrace_close (ddescriptor, error_callback, data);
          return -1;
        }
    }

  return ddescriptor;
}

/* Return the length (without the trailing 0) of a COFF short name.  */

static size_t
coff_short_name_len (const char *name)
{
  int i;

  for (i = 0; i < 8; i++)
    if (name[i] == 0)
      return i;
  return 8;
}

/* Return true iff COFF short name CNAME is the same as NAME (a NUL-terminated
   string).  */

static int
coff_short_name_eq (const char *name, const char *cname)
{
  int i;

  for (i = 0; i < 8; i++)
    {
      if (name[i] != cname[i])
	return 0;
      if (name[i] == 0)
	return 1;
    }
  return name[8] == 0;
}

/* Return true iff NAME is the same as string at offset OFF.  */

static int
coff_long_name_eq (const char *name, unsigned int off,
		   struct backtrace_view *str_view)
{
  if (off >= str_view->len)
    return 0;
  return strcmp (name, (const char *)str_view->data + off) == 0;
}

/* Compare struct coff_symbol for qsort.  */

static int
coff_symbol_compare (const void *v1, const void *v2)
{
  const struct coff_symbol *e1 = (const struct coff_symbol *) v1;
  const struct coff_symbol *e2 = (const struct coff_symbol *) v2;

  if (e1->address < e2->address)
    return -1;
  else if (e1->address > e2->address)
    return 1;
  else
    return 0;
}

/* Convert SYM to internal (and aligned) format ISYM, using string table
   from STRTAB and STRTAB_SIZE, and number of sections SECTS_NUM.
   Return -1 in case of error (invalid section number or string index).  */

static int
coff_expand_symbol (b_coff_internal_symbol *isym,
		    const b_coff_external_symbol *sym,
		    uint16_t sects_num,
		    const unsigned char *strtab, size_t strtab_size)
{
  isym->type = coff_read2 (sym->type);
  isym->sec = coff_read2 (sym->section_number);
  isym->sc = sym->storage_class;

  if (isym->sec > 0 && (uint16_t) isym->sec > sects_num)
    return -1;
  if (sym->name.short_name[0] != 0)
    isym->name = sym->name.short_name;
  else
    {
      uint32_t off = coff_read4 (sym->name.long_name.off);

      if (off >= strtab_size)
	return -1;
      isym->name = (const char *) strtab + off;
    }
  return 0;
}

/* Return true iff SYM is a defined symbol for a function.  Data symbols
   aren't considered because they aren't easily identified (same type as
   section names, presence of symbols defined by the linker script).  */

static int
coff_is_function_symbol (const b_coff_internal_symbol *isym)
{
  return (isym->type >> N_TBSHFT) == IMAGE_SYM_DTYPE_FUNCTION
    && isym->sec > 0;
}

/* Initialize the symbol table info for coff_syminfo.  */

static int
coff_initialize_syminfo (struct backtrace_state *state,
			 struct libbacktrace_base_address base_address,
			 int is_64, const b_coff_section_header *sects,
			 size_t sects_num, const b_coff_external_symbol *syms,
			 size_t syms_size, const unsigned char *strtab,
			 size_t strtab_size,
			 backtrace_error_callback error_callback,
			 void *data, struct coff_syminfo_data *sdata)
{
  size_t syms_count;
  char *coff_symstr;
  size_t coff_symstr_len;
  size_t coff_symbol_count;
  size_t coff_symbol_size;
  struct coff_symbol *coff_symbols;
  struct coff_symbol *coff_sym;
  char *coff_str;
  size_t i;

  syms_count = syms_size / SYM_SZ;

  /* We only care about function symbols.  Count them.  Also count size of
     strings for in-symbol names.  */
  coff_symbol_count = 0;
  coff_symstr_len = 0;
  for (i = 0; i < syms_count; ++i)
    {
      const b_coff_external_symbol *asym = &syms[i];
      b_coff_internal_symbol isym;

      if (coff_expand_symbol (&isym, asym, sects_num, strtab, strtab_size) < 0)
	{
	  error_callback (data, "invalid section or offset in coff symbol", 0);
	  return 0;
	}
      if (coff_is_function_symbol (&isym))
	{
	  ++coff_symbol_count;
	  if (asym->name.short_name[0] != 0)
	    coff_symstr_len += coff_short_name_len (asym->name.short_name) + 1;
	}

      i += asym->number_of_aux_symbols;
    }

  coff_symbol_size = (coff_symbol_count + 1) * sizeof (struct coff_symbol);
  coff_symbols = ((struct coff_symbol *)
		  backtrace_alloc (state, coff_symbol_size, error_callback,
				   data));
  if (coff_symbols == NULL)
    return 0;

  /* Allocate memory for symbols strings.  */
  if (coff_symstr_len > 0)
    {
      coff_symstr = ((char *)
		     backtrace_alloc (state, coff_symstr_len, error_callback,
				      data));
      if (coff_symstr == NULL)
	{
	  backtrace_free (state, coff_symbols, coff_symbol_size,
			  error_callback, data);
	  return 0;
	}
    }
  else
    coff_symstr = NULL;

  /* Copy symbols.  */
  coff_sym = coff_symbols;
  coff_str = coff_symstr;
  for (i = 0; i < syms_count; ++i)
    {
      const b_coff_external_symbol *asym = &syms[i];
      b_coff_internal_symbol isym;

      if (coff_expand_symbol (&isym, asym, sects_num, strtab, strtab_size))
	{
	  /* Should not fail, as it was already tested in the previous
	     loop.  */
	  abort ();
	}
      if (coff_is_function_symbol (&isym))
	{
	  const char *name;
	  int16_t secnum;

	  if (asym->name.short_name[0] != 0)
	    {
	      size_t len = coff_short_name_len (isym.name);
	      name = coff_str;
	      memcpy (coff_str, isym.name, len);
	      coff_str[len] = 0;
	      coff_str += len + 1;
	    }
	  else
	    name = isym.name;

	  if (!is_64)
	    {
	      /* Strip leading '_'.  */
	      if (name[0] == '_')
		name++;
	    }

	  /* Symbol value is section relative, so we need to read the address
	     of its section.  */
	  secnum = coff_read2 (asym->section_number);

	  coff_sym->name = name;
	  coff_sym->address =
	    libbacktrace_add_base ((coff_read4 (asym->value)
				    + sects[secnum - 1].virtual_address),
				   base_address);
	  coff_sym++;
	}

      i += asym->number_of_aux_symbols;
    }

  /* End of symbols marker.  */
  coff_sym->name = NULL;
  coff_sym->address = -1;

  backtrace_qsort (coff_symbols, coff_symbol_count,
		   sizeof (struct coff_symbol), coff_symbol_compare);

  sdata->next = NULL;
  sdata->symbols = coff_symbols;
  sdata->count = coff_symbol_count;

  return 1;
}

/* Add EDATA to the list in STATE.  */

static void
coff_add_syminfo_data (struct backtrace_state *state,
		       struct coff_syminfo_data *sdata)
{
  if (!state->threaded)
    {
      struct coff_syminfo_data **pp;

      for (pp = (struct coff_syminfo_data **) (void *) &state->syminfo_data;
	   *pp != NULL;
	   pp = &(*pp)->next)
	;
      *pp = sdata;
    }
  else
    {
      while (1)
	{
	  struct coff_syminfo_data **pp;

	  pp = (struct coff_syminfo_data **) (void *) &state->syminfo_data;

	  while (1)
	    {
	      struct coff_syminfo_data *p;

	      p = backtrace_atomic_load_pointer (pp);

	      if (p == NULL)
		break;

	      pp = &p->next;
	    }

	  if (__sync_bool_compare_and_swap (pp, NULL, sdata))
	    break;
	}
    }
}

/* Compare an ADDR against an elf_symbol for bsearch.  We allocate one
   extra entry in the array so that this can look safely at the next
   entry.  */

static int
coff_symbol_search (const void *vkey, const void *ventry)
{
  const uintptr_t *key = (const uintptr_t *) vkey;
  const struct coff_symbol *entry = (const struct coff_symbol *) ventry;
  uintptr_t addr;

  addr = *key;
  if (addr < entry->address)
    return -1;
  else if (addr >= entry[1].address)
    return 1;
  else
    return 0;
}

/* Return the symbol name and value for an ADDR.  */

static void
coff_syminfo (struct backtrace_state *state, uintptr_t addr,
	      backtrace_syminfo_callback callback,
	      backtrace_error_callback error_callback ATTRIBUTE_UNUSED,
	      void *data)
{
  struct coff_syminfo_data *sdata;
  struct coff_symbol *sym = NULL;

  if (!state->threaded)
    {
      for (sdata = (struct coff_syminfo_data *) state->syminfo_data;
	   sdata != NULL;
	   sdata = sdata->next)
	{
	  sym = ((struct coff_symbol *)
		 bsearch (&addr, sdata->symbols, sdata->count,
			  sizeof (struct coff_symbol), coff_symbol_search));
	  if (sym != NULL)
	    break;
	}
    }
  else
    {
      struct coff_syminfo_data **pp;

      pp = (struct coff_syminfo_data **) (void *) &state->syminfo_data;
      while (1)
	{
	  sdata = backtrace_atomic_load_pointer (pp);
	  if (sdata == NULL)
	    break;

	  sym = ((struct coff_symbol *)
		 bsearch (&addr, sdata->symbols, sdata->count,
			  sizeof (struct coff_symbol), coff_symbol_search));
	  if (sym != NULL)
	    break;

	  pp = &sdata->next;
	}
    }

  if (sym == NULL)
    callback (data, addr, NULL, 0, 0);
  else
    callback (data, addr, sym->name, sym->address, 0);
}

/* Add the backtrace data for one PE/COFF file.  Returns 1 on success,
   0 on failure (in both cases descriptor is closed).  */

static int
coff_add (struct backtrace_state *state, const char *filename, int descriptor,
	  backtrace_error_callback error_callback, void *data,
	  fileline *fileline_fn, int *found_sym, int *found_dwarf,
	  uintptr_t module_handle ATTRIBUTE_UNUSED)
{
  struct backtrace_view fhdr_view;
  off_t fhdr_off;
  int magic_ok;
  b_coff_file_header fhdr;
  off_t opt_sects_off;
  size_t opt_sects_size;
  unsigned int sects_num;
  struct backtrace_view sects_view;
  int sects_view_valid;
  const b_coff_optional_header *opt_hdr;
  const b_coff_section_header *sects;
  struct backtrace_view str_view;
  int str_view_valid;
  size_t str_size;
  off_t str_off;
  struct backtrace_view syms_view;
  off_t syms_off;
  size_t syms_size;
  int syms_view_valid;
  unsigned int syms_num;
  unsigned int i;
  struct debug_section_info sections[DEBUG_MAX];
  off_t min_offset;
  off_t max_offset;
  struct backtrace_view debug_view;
  int debug_view_valid;
  const char *debuglink_name;
  uint32_t debuglink_crc;
  int debuglink_view_valid;
  struct backtrace_view debuglink_view;
  const char *debugaltlink_name;
  int debugaltlink_view_valid;
  struct backtrace_view debugaltlink_view;
  int is_64;
  struct libbacktrace_base_address image_base;
  struct libbacktrace_base_address base_address;
  struct dwarf_sections dwarf_sections;

  *found_sym = 0;
  *found_dwarf = 0;

  sects_view_valid = 0;
  syms_view_valid = 0;
  str_view_valid = 0;
  debug_view_valid = 0;
  debuglink_view_valid = 0;
  debugaltlink_view_valid = 0;
  debuglink_name = NULL;
  debuglink_crc = 0;
  debugaltlink_name = NULL;

  /* Map the MS-DOS stub (if any) and extract file header offset.  */
  if (!backtrace_get_view (state, descriptor, 0, 0x40, error_callback,
			   data, &fhdr_view))
    goto fail;

  {
    const unsigned char *vptr = fhdr_view.data;

    if (vptr[0] == 'M' && vptr[1] == 'Z')
      fhdr_off = coff_read4 (vptr + 0x3c);
    else
      fhdr_off = 0;
  }

  backtrace_release_view (state, &fhdr_view, error_callback, data);

  /* Map the coff file header.  */
  if (!backtrace_get_view (state, descriptor, fhdr_off,
			   sizeof (b_coff_file_header) + 4,
			   error_callback, data, &fhdr_view))
    goto fail;

  if (fhdr_off != 0)
    {
      const char *magic = (const char *) fhdr_view.data;
      magic_ok = memcmp (magic, "PE\0", 4) == 0;
      fhdr_off += 4;

      memcpy (&fhdr, (const unsigned char *) fhdr_view.data + 4, sizeof fhdr);
    }
  else
    {
      memcpy (&fhdr, fhdr_view.data, sizeof fhdr);
      /* TODO: test fhdr.machine for coff but non-PE platforms.  */
      magic_ok = 0;
    }
  backtrace_release_view (state, &fhdr_view, error_callback, data);

  if (!magic_ok)
    {
      error_callback (data, "executable file is not COFF", 0);
      goto fail;
    }

  sects_num = fhdr.number_of_sections;
  syms_num = fhdr.number_of_symbols;

  opt_sects_off = fhdr_off + sizeof (fhdr);
  opt_sects_size = (fhdr.size_of_optional_header
		    + sects_num * sizeof (b_coff_section_header));

  /* To translate PC to file/line when using DWARF, we need to find
     the .debug_info and .debug_line sections.  */

  /* Read the optional header and the section headers.  */

  if (!backtrace_get_view (state, descriptor, opt_sects_off, opt_sects_size,
			   error_callback, data, &sects_view))
    goto fail;
  sects_view_valid = 1;
  opt_hdr = (const b_coff_optional_header *) sects_view.data;
  sects = (const b_coff_section_header *)
    ((const unsigned char *) sects_view.data + fhdr.size_of_optional_header);

  is_64 = 0;
  memset (&image_base, 0, sizeof image_base);
  if (fhdr.size_of_optional_header > sizeof (*opt_hdr))
    {
      if (opt_hdr->magic == PE_MAGIC)
	image_base.m = opt_hdr->u.pe.image_base;
      else if (opt_hdr->magic == PEP_MAGIC)
	{
	  image_base.m = opt_hdr->u.pep.image_base;
	  is_64 = 1;
	}
      else
	{
	  error_callback (data, "bad magic in PE optional header", 0);
	  goto fail;
	}
    }

  /* Read the symbol table and the string table.  */

  if (fhdr.pointer_to_symbol_table == 0)
    {
      /* No symbol table, no string table.  */
      str_off = 0;
      str_size = 0;
      syms_num = 0;
      syms_size = 0;
    }
  else
    {
      /* Symbol table is followed by the string table.  The string table
	 starts with its length (on 4 bytes).
	 Map the symbol table and the length of the string table.  */
      syms_off = fhdr.pointer_to_symbol_table;
      syms_size = syms_num * SYM_SZ;

      if (!backtrace_get_view (state, descriptor, syms_off, syms_size + 4,
			       error_callback, data, &syms_view))
	goto fail;
      syms_view_valid = 1;

      str_size = coff_read4 ((const unsigned char *) syms_view.data
			     + syms_size);

      str_off = syms_off + syms_size;

      if (str_size > 4)
	{
	  /* Map string table (including the length word).  */

	  if (!backtrace_get_view (state, descriptor, str_off, str_size,
				   error_callback, data, &str_view))
	    goto fail;
	  str_view_valid = 1;
	}
    }

  memset (sections, 0, sizeof sections);

  /* Look for the symbol table.  */
  for (i = 0; i < sects_num; ++i)
    {
      const b_coff_section_header *s = sects + i;
      unsigned int str_off;
      int j;

      if (s->name[0] == '/')
	{
	  /* Extended section name.  */
	  str_off = atoi (s->name + 1);
	}
      else
	str_off = 0;

      for (j = 0; j < (int) DEBUG_MAX; ++j)
	{
	  const char *dbg_name = debug_section_names[j];
	  int match;

	  if (str_off != 0)
	    match = coff_long_name_eq (dbg_name, str_off, &str_view);
	  else
	    match = coff_short_name_eq (dbg_name, s->name);
	  if (match)
	    {
	      sections[j].offset = s->pointer_to_raw_data;
	      sections[j].size = s->virtual_size <= s->size_of_raw_data ?
		s->virtual_size : s->size_of_raw_data;
	      break;
	    }
      /* Read .gnu_debuglink and .gnu_debugaltlink if present.  */
      if (s->name[0] == '/')
        str_off = atoi (s->name + 1);
      else
        str_off = 0;

      /* Compare names for .gnu_debuglink and .gnu_debugaltlink.  */
      if ((!debuglink_view_valid) && (str_off != 0 ?
           coff_long_name_eq (".gnu_debuglink", str_off, &str_view) :
           coff_short_name_eq (".gnu_debuglink", s->name)))
        {
          if (!backtrace_get_view (state, descriptor, s->pointer_to_raw_data,
                                   s->virtual_size <= s->size_of_raw_data ?
                                   s->virtual_size : s->size_of_raw_data,
                                   error_callback, data, &debuglink_view))
            goto fail;
          debuglink_view_valid = 1;
          /* Extract name and CRC from view. */
          {
            const char *debuglink_data = (const char *) debuglink_view.data;
            size_t crc_offset = strnlen (debuglink_data,
                                         s->virtual_size <= s->size_of_raw_data ?
                                         s->virtual_size : s->size_of_raw_data);
            crc_offset = (crc_offset + 3) & ~3;
            if (crc_offset + 4 <= (size_t) (s->virtual_size <= s->size_of_raw_data ?
                                            s->virtual_size : s->size_of_raw_data))
              {
                debuglink_name = debuglink_data;
                debuglink_crc = *(const uint32_t*) (debuglink_data + crc_offset);
                {
                  char _msg[512];
                  snprintf (_msg, sizeof (_msg), "Found .gnu_debuglink: %s CRC: 0x%08x (original: %s)",
                            debuglink_name, debuglink_crc, filename ? filename : "");
                  error_callback (data, _msg, 0);
                }
              }
          }
        }
      if ((!debugaltlink_view_valid) && (str_off != 0 ?
           coff_long_name_eq (".gnu_debugaltlink", str_off, &str_view) :
           coff_short_name_eq (".gnu_debugaltlink", s->name)))
        {
          if (!backtrace_get_view (state, descriptor, s->pointer_to_raw_data,
                                   s->virtual_size <= s->size_of_raw_data ?
                                   s->virtual_size : s->size_of_raw_data,
                                   error_callback, data, &debugaltlink_view))
            goto fail;
          debugaltlink_view_valid = 1;
          debugaltlink_name = (const char *) debugaltlink_view.data;
        }
	}
    }

  if (syms_num != 0)
    {
      struct coff_syminfo_data *sdata;

      sdata = ((struct coff_syminfo_data *)
	       backtrace_alloc (state, sizeof *sdata, error_callback, data));
      if (sdata == NULL)
	goto fail;

      if (!coff_initialize_syminfo (state, image_base, is_64,
				    sects, sects_num,
				    syms_view.data, syms_size,
				    str_view.data, str_size,
				    error_callback, data, sdata))
	{
	  backtrace_free (state, sdata, sizeof *sdata, error_callback, data);
	  goto fail;
	}

      *found_sym = 1;

      coff_add_syminfo_data (state, sdata);
    }

  backtrace_release_view (state, &sects_view, error_callback, data);
  sects_view_valid = 0;
  if (syms_view_valid)
    {
      backtrace_release_view (state, &syms_view, error_callback, data);
      syms_view_valid = 0;
    }

  /* If a separate debug file is specified via .gnu_debuglink, try to open
     it and use that file's debug info instead. */
  if (debuglink_name != NULL)
    {
      int d;
      d = coff_open_debugfile_by_debuglink (state, filename, debuglink_name,
                                            debuglink_crc, error_callback, data);
      if (d >= 0)
        {
          int ret;

          if (debuglink_view_valid)
            backtrace_release_view (state, &debuglink_view, error_callback, data);
          if (debugaltlink_view_valid)
            backtrace_release_view (state, &debugaltlink_view, error_callback, data);
          {
            char _msg_use[512];
            snprintf (_msg_use, sizeof (_msg_use), "Using external debug file specified in .gnu_debuglink: %s", debuglink_name);
            error_callback (data, _msg_use, 0);
          }
          ret = coff_add (state, debuglink_name, d, error_callback, data, fileline_fn,
                          found_sym, found_dwarf, module_handle);
          if (ret <= 0)
            {
              /* External parse failed: report and close external descriptor,
                  then fall back to using embedded DWARF in the original file. */
              {
                char _msg_pf[512];
                snprintf (_msg_pf, sizeof (_msg_pf),
                          "Failed to parse external debug file '%s' specified in .gnu_debuglink for %s; falling back to embedded DWARF",
                          debuglink_name, filename ? filename : "(unknown)");
                error_callback (data, _msg_pf, 0);
              }
              backtrace_close (d, error_callback, data);
              /* Do not return; continue and try embedded debug sections. */
            }
          else
            {
              if (descriptor >= 0)
                backtrace_close (descriptor, error_callback, data);
              return ret;
            }
        }
      else
        {
          /* Could not open or validate external debug file; report fallback. */
          char _msg_of[512];
          snprintf (_msg_of, sizeof (_msg_of),
                    "Could not open/validate external debug file '%s' from .gnu_debuglink for %s; falling back to embedded DWARF if present",
                    debuglink_name, filename ? filename : "(unknown)");
          error_callback (data, _msg_of, 0);
        }
    }
  if (debugaltlink_name != NULL)
    {
      int d;
      d = coff_open_debugfile_by_debuglink (state, filename, debugaltlink_name,
                                            0, error_callback, data);
      if (d >= 0)
        {
          int ret;

          if (debuglink_view_valid)
            backtrace_release_view (state, &debuglink_view, error_callback, data);
          if (debugaltlink_view_valid)
            backtrace_release_view (state, &debugaltlink_view, error_callback, data);
          ret = coff_add (state, filename, d, error_callback, data, fileline_fn,
                          found_sym, found_dwarf, module_handle);
          if (ret <= 0)
            {
              {
                char _msg_pf2[512];
                snprintf (_msg_pf2, sizeof (_msg_pf2),
                          "Failed to parse external debugaltlink file '%s' for %s; falling back to embedded DWARF",
                          debugaltlink_name, filename ? filename : "(unknown)");
                error_callback (data, _msg_pf2, 0);
              }
              backtrace_close (d, error_callback, data);
              /* Fall back to embedded DWARF in the original file. */
            }
          else
            {
              if (descriptor >= 0)
                backtrace_close (descriptor, error_callback, data);
              return ret;
            }
        }
      else
        {
          char _msg_of2[512];
          snprintf (_msg_of2, sizeof (_msg_of2),
                    "Could not open/validate external debugaltlink file '%s' for %s; falling back to embedded DWARF if present",
                    debugaltlink_name, filename ? filename : "(unknown)");
          error_callback (data, _msg_of2, 0);
        }
    }

  /* Read all the debug sections in a single view, since they are
     probably adjacent in the file.  We never release this view.  */

  min_offset = 0;
  max_offset = 0;
  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      off_t end;

      if (sections[i].size == 0)
	continue;
      if (min_offset == 0 || sections[i].offset < min_offset)
	min_offset = sections[i].offset;
      end = sections[i].offset + sections[i].size;
      if (end > max_offset)
	max_offset = end;
    }
  if (min_offset == 0 || max_offset == 0)
    {
      if (!backtrace_close (descriptor, error_callback, data))
	goto fail;
      *fileline_fn = coff_nodebug;
      return 1;
    }

  if (!backtrace_get_view (state, descriptor, min_offset,
			   max_offset - min_offset,
			   error_callback, data, &debug_view))
    goto fail;
  debug_view_valid = 1;

  /* We've read all we need from the executable.  */
  if (!backtrace_close (descriptor, error_callback, data))
    goto fail;
  descriptor = -1;

  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      size_t size = sections[i].size;
      dwarf_sections.size[i] = size;
      if (size == 0)
	dwarf_sections.data[i] = NULL;
      else
	dwarf_sections.data[i] = ((const unsigned char *) debug_view.data
				  + (sections[i].offset - min_offset));
    }

  memset (&base_address, 0, sizeof base_address);
#ifdef HAVE_WINDOWS_H
  base_address.m = module_handle - image_base.m;
#endif

  if (!backtrace_dwarf_add (state, base_address, &dwarf_sections,
			    0, /* FIXME: is_bigendian */
			    NULL, /* altlink */
			    error_callback, data, fileline_fn,
			    NULL /* returned fileline_entry */))
    goto fail;

  *found_dwarf = 1;

  return 1;

 fail:
  if (sects_view_valid)
    backtrace_release_view (state, &sects_view, error_callback, data);
  if (str_view_valid)
    backtrace_release_view (state, &str_view, error_callback, data);
  if (syms_view_valid)
    backtrace_release_view (state, &syms_view, error_callback, data);
  if (debug_view_valid)
    backtrace_release_view (state, &debug_view, error_callback, data);
  if (descriptor != -1)
    backtrace_close (descriptor, error_callback, data);
  return 0;
}

#ifdef HAVE_WINDOWS_H
struct dll_notification_context
{
  struct backtrace_state *state;
  backtrace_error_callback error_callback;
  void *data;
};

static VOID CALLBACK
dll_notification (ULONG reason,
		  struct dll_notification_data *notification_data,
		  PVOID context)
{
  char module_name[MAX_PATH];
  int descriptor;
  struct dll_notification_context* dll_context =
    (struct dll_notification_context*) context;
  struct backtrace_state *state = dll_context->state;
  void *data = dll_context->data;
  backtrace_error_callback error_callback = dll_context->error_callback;
  fileline fileline;
  int found_sym;
  int found_dwarf;
  HMODULE module_handle;

  if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
    return;

  if (!GetModuleHandleExW ((GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT),
			   (wchar_t*) notification_data->dll_base,
			   &module_handle))
    return;

  if (!GetModuleFileNameA ((HMODULE) module_handle, module_name, MAX_PATH - 1))
    return;

  descriptor = backtrace_open (module_name, error_callback, data, NULL);

  if (descriptor < 0)
    return;

  coff_add (state, module_name, descriptor, error_callback, data, &fileline, &found_sym,
	    &found_dwarf, (uintptr_t) module_handle);
}
#endif /* defined(HAVE_WINDOWS_H) */

/* Initialize the backtrace data we need from an ELF executable.  At
   the ELF level, all we need to do is find the debug info
   sections.  */

int
backtrace_initialize (struct backtrace_state *state,
		      const char *filename ATTRIBUTE_UNUSED, int descriptor,
		      backtrace_error_callback error_callback,
		      void *data, fileline *fileline_fn)
{
  int ret;
  int found_sym;
  int found_dwarf;
  fileline coff_fileline_fn;
  uintptr_t module_handle = 0;
#ifdef HAVE_TLHELP32_H
  fileline module_fileline_fn;
  int module_found_sym;
  HANDLE snapshot;
#endif

#ifdef HAVE_WINDOWS_H
  HMODULE nt_dll_handle;

  module_handle = (uintptr_t) GetModuleHandle (NULL);
#endif

  ret = coff_add (state, filename, descriptor, error_callback, data,
		  &coff_fileline_fn, &found_sym, &found_dwarf, module_handle);
  if (!ret)
    return 0;

#ifdef HAVE_TLHELP32_H
  do
    {
      snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPMODULE, 0);
    }
  while (snapshot == INVALID_HANDLE_VALUE
	 && GetLastError () == ERROR_BAD_LENGTH);

  if (snapshot != INVALID_HANDLE_VALUE)
    {
      MODULEENTRY32 entry;
      BOOL ok;
      entry.dwSize = sizeof (MODULEENTRY32);

      for (ok = Module32First (snapshot, &entry); ok; ok = Module32Next (snapshot, &entry))
	{
	  if (strcmp (filename, entry.szExePath) == 0)
	    continue;

	  module_handle = (uintptr_t) entry.hModule;
	  if (module_handle == 0)
	    continue;

	  descriptor = backtrace_open (entry.szExePath, error_callback, data,
				       NULL);
	  if (descriptor < 0)
	    continue;

	  coff_add (state, entry.szExePath, descriptor, error_callback, data,
		    &module_fileline_fn, &module_found_sym, &found_dwarf,
		    module_handle);
	  if (module_found_sym)
	    found_sym = 1;
	}

      CloseHandle (snapshot);
    }
#endif

#ifdef HAVE_WINDOWS_H
  nt_dll_handle = GetModuleHandleW (L"ntdll.dll");
  if (nt_dll_handle)
    {
      LDR_REGISTER_FUNCTION register_func;
      const char register_name[] = "LdrRegisterDllNotification";
      register_func = (void*) GetProcAddress (nt_dll_handle,
					      register_name);

      if (register_func)
	{
	  PVOID cookie;
	  struct dll_notification_context *context
	    = backtrace_alloc (state,
			       sizeof (struct dll_notification_context),
			       error_callback, data);

	  if (context)
	    {
	      context->state = state;
	      context->data = data;
	      context->error_callback = error_callback;

	      register_func (0, &dll_notification, context, &cookie);
	    }
	}
    }
#endif /* defined(HAVE_WINDOWS_H) */

  if (!state->threaded)
    {
      if (found_sym)
	state->syminfo_fn = coff_syminfo;
      else if (state->syminfo_fn == NULL)
	state->syminfo_fn = coff_nosyms;
    }
  else
    {
      if (found_sym)
	backtrace_atomic_store_pointer (&state->syminfo_fn, coff_syminfo);
      else
	(void) __sync_bool_compare_and_swap (&state->syminfo_fn, NULL,
					     coff_nosyms);
    }

  if (!state->threaded)
    {
      if (state->fileline_fn == NULL || state->fileline_fn == coff_nodebug)
	*fileline_fn = coff_fileline_fn;
    }
  else
    {
      fileline current_fn;

      current_fn = backtrace_atomic_load_pointer (&state->fileline_fn);
      if (current_fn == NULL || current_fn == coff_nodebug)
	*fileline_fn = coff_fileline_fn;
    }

  return 1;
}
