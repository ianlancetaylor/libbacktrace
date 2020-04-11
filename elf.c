/* elf.c -- Get debug data from an ELF file for backtraces.
   Copyright (C) 2012-2020 Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Google.
   MiniDebugInfo support by Anton Yurievich Bornev, Bastion Ltd.
   xz decompressor by Lasse Collin <lasse.collin@tukaani.org>
	              Igor Pavlov <http://7-zip.org/>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_DL_ITERATE_PHDR
#include <link.h>
#endif

#include "backtrace.h"
#include "internal.h"

#ifndef S_ISLNK
 #ifndef S_IFLNK
  #define S_IFLNK 0120000
 #endif
 #ifndef S_IFMT
  #define S_IFMT 0170000
 #endif
 #define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif

#ifndef __GNUC__
#define __builtin_prefetch(p, r, l)
#define unlikely(x) (x)
#else
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef min
  #define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#define min_t(type, x, y) min(x, y)

#if !defined(HAVE_DECL_STRNLEN) || !HAVE_DECL_STRNLEN

/* If strnlen is not declared, provide our own version.  */

static size_t
xstrnlen (const char *s, size_t maxlen)
{
  size_t i;

  for (i = 0; i < maxlen; ++i)
    if (s[i] == '\0')
      break;
  return i;
}

#define strnlen xstrnlen

#endif

#ifndef HAVE_LSTAT

/* Dummy version of lstat for systems that don't have it.  */

static int
xlstat (const char *path ATTRIBUTE_UNUSED, struct stat *st ATTRIBUTE_UNUSED)
{
  return -1;
}

#define lstat xlstat

#endif

#ifndef HAVE_READLINK

/* Dummy version of readlink for systems that don't have it.  */

static ssize_t
xreadlink (const char *path ATTRIBUTE_UNUSED, char *buf ATTRIBUTE_UNUSED,
	   size_t bufsz ATTRIBUTE_UNUSED)
{
  return -1;
}

#define readlink xreadlink

#endif

#ifndef HAVE_DL_ITERATE_PHDR

/* Dummy version of dl_iterate_phdr for systems that don't have it.  */

#define dl_phdr_info x_dl_phdr_info
#define dl_iterate_phdr x_dl_iterate_phdr

struct dl_phdr_info
{
  uintptr_t dlpi_addr;
  const char *dlpi_name;
};

static int
dl_iterate_phdr (int (*callback) (struct dl_phdr_info *,
				  size_t, void *) ATTRIBUTE_UNUSED,
		 void *data ATTRIBUTE_UNUSED)
{
  return 0;
}

#endif /* ! defined (HAVE_DL_ITERATE_PHDR) */

/* The configure script must tell us whether we are 32-bit or 64-bit
   ELF.  We could make this code test and support either possibility,
   but there is no point.  This code only works for the currently
   running executable, which means that we know the ELF mode at
   configure time.  */

#if BACKTRACE_ELF_SIZE != 32 && BACKTRACE_ELF_SIZE != 64
#error "Unknown BACKTRACE_ELF_SIZE"
#endif

/* <link.h> might #include <elf.h> which might define our constants
   with slightly different values.  Undefine them to be safe.  */

#undef EI_NIDENT
#undef EI_MAG0
#undef EI_MAG1
#undef EI_MAG2
#undef EI_MAG3
#undef EI_CLASS
#undef EI_DATA
#undef EI_VERSION
#undef ELF_MAG0
#undef ELF_MAG1
#undef ELF_MAG2
#undef ELF_MAG3
#undef ELFCLASS32
#undef ELFCLASS64
#undef ELFDATA2LSB
#undef ELFDATA2MSB
#undef EV_CURRENT
#undef ET_DYN
#undef EM_PPC64
#undef EF_PPC64_ABI
#undef SHN_LORESERVE
#undef SHN_XINDEX
#undef SHN_UNDEF
#undef SHT_PROGBITS
#undef SHT_SYMTAB
#undef SHT_STRTAB
#undef SHT_DYNSYM
#undef SHF_COMPRESSED
#undef STT_OBJECT
#undef STT_FUNC
#undef NT_GNU_BUILD_ID
#undef ELFCOMPRESS_ZLIB

/* Basic types.  */

typedef uint16_t b_elf_half;    /* Elf_Half.  */
typedef uint32_t b_elf_word;    /* Elf_Word.  */
typedef int32_t  b_elf_sword;   /* Elf_Sword.  */

#if BACKTRACE_ELF_SIZE == 32

typedef uint32_t b_elf_addr;    /* Elf_Addr.  */
typedef uint32_t b_elf_off;     /* Elf_Off.  */

typedef uint32_t b_elf_wxword;  /* 32-bit Elf_Word, 64-bit ELF_Xword.  */

#else

typedef uint64_t b_elf_addr;    /* Elf_Addr.  */
typedef uint64_t b_elf_off;     /* Elf_Off.  */
typedef uint64_t b_elf_xword;   /* Elf_Xword.  */
typedef int64_t  b_elf_sxword;  /* Elf_Sxword.  */

typedef uint64_t b_elf_wxword;  /* 32-bit Elf_Word, 64-bit ELF_Xword.  */

#endif

/* Data structures and associated constants.  */

#define EI_NIDENT 16

typedef struct {
  unsigned char	e_ident[EI_NIDENT];	/* ELF "magic number" */
  b_elf_half	e_type;			/* Identifies object file type */
  b_elf_half	e_machine;		/* Specifies required architecture */
  b_elf_word	e_version;		/* Identifies object file version */
  b_elf_addr	e_entry;		/* Entry point virtual address */
  b_elf_off	e_phoff;		/* Program header table file offset */
  b_elf_off	e_shoff;		/* Section header table file offset */
  b_elf_word	e_flags;		/* Processor-specific flags */
  b_elf_half	e_ehsize;		/* ELF header size in bytes */
  b_elf_half	e_phentsize;		/* Program header table entry size */
  b_elf_half	e_phnum;		/* Program header table entry count */
  b_elf_half	e_shentsize;		/* Section header table entry size */
  b_elf_half	e_shnum;		/* Section header table entry count */
  b_elf_half	e_shstrndx;		/* Section header string table index */
} b_elf_ehdr;  /* Elf_Ehdr.  */

#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS32 1
#define ELFCLASS64 2

#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#define EV_CURRENT 1

#define ET_DYN 3

#define EM_PPC64 21
#define EF_PPC64_ABI 3

typedef struct {
  b_elf_word	sh_name;		/* Section name, index in string tbl */
  b_elf_word	sh_type;		/* Type of section */
  b_elf_wxword	sh_flags;		/* Miscellaneous section attributes */
  b_elf_addr	sh_addr;		/* Section virtual addr at execution */
  b_elf_off	sh_offset;		/* Section file offset */
  b_elf_wxword	sh_size;		/* Size of section in bytes */
  b_elf_word	sh_link;		/* Index of another section */
  b_elf_word	sh_info;		/* Additional section information */
  b_elf_wxword	sh_addralign;		/* Section alignment */
  b_elf_wxword	sh_entsize;		/* Entry size if section holds table */
} b_elf_shdr;  /* Elf_Shdr.  */

#define SHN_UNDEF	0x0000		/* Undefined section */
#define SHN_LORESERVE	0xFF00		/* Begin range of reserved indices */
#define SHN_XINDEX	0xFFFF		/* Section index is held elsewhere */

#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_DYNSYM 11

#define SHF_COMPRESSED 0x800

#if BACKTRACE_ELF_SIZE == 32

typedef struct
{
  b_elf_word	st_name;		/* Symbol name, index in string tbl */
  b_elf_addr	st_value;		/* Symbol value */
  b_elf_word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol binding and type */
  unsigned char	st_other;		/* Visibility and other data */
  b_elf_half	st_shndx;		/* Symbol section index */
} b_elf_sym;  /* Elf_Sym.  */

#else /* BACKTRACE_ELF_SIZE != 32 */

typedef struct
{
  b_elf_word	st_name;		/* Symbol name, index in string tbl */
  unsigned char	st_info;		/* Symbol binding and type */
  unsigned char	st_other;		/* Visibility and other data */
  b_elf_half	st_shndx;		/* Symbol section index */
  b_elf_addr	st_value;		/* Symbol value */
  b_elf_xword	st_size;		/* Symbol size */
} b_elf_sym;  /* Elf_Sym.  */

#endif /* BACKTRACE_ELF_SIZE != 32 */

#define STT_OBJECT 1
#define STT_FUNC 2

typedef struct
{
  uint32_t namesz;
  uint32_t descsz;
  uint32_t type;
  char name[1];
} b_elf_note;

#define NT_GNU_BUILD_ID 3

#if BACKTRACE_ELF_SIZE == 32

typedef struct
{
  b_elf_word	ch_type;		/* Compresstion algorithm */
  b_elf_word	ch_size;		/* Uncompressed size */
  b_elf_word	ch_addralign;		/* Alignment for uncompressed data */
} b_elf_chdr;  /* Elf_Chdr */

#else /* BACKTRACE_ELF_SIZE != 32 */

typedef struct
{
  b_elf_word	ch_type;		/* Compression algorithm */
  b_elf_word	ch_reserved;		/* Reserved */
  b_elf_xword	ch_size;		/* Uncompressed size */
  b_elf_xword	ch_addralign;		/* Alignment for uncompressed data */
} b_elf_chdr;  /* Elf_Chdr */

#endif /* BACKTRACE_ELF_SIZE != 32 */

#define ELFCOMPRESS_ZLIB 1

/* Names of sections, indexed by enum dwarf_section in internal.h.  */

static const char * const dwarf_section_names[DEBUG_MAX] =
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
  /* Section contents, after read from file.  */
  const unsigned char *data;
  /* Whether the SHF_COMPRESSED flag is set for the section.  */
  int compressed;
};

/* Information we keep for an ELF symbol.  */

struct elf_symbol
{
  /* The name of the symbol.  */
  const char *name;
  /* The address of the symbol.  */
  uintptr_t address;
  /* The size of the symbol.  */
  size_t size;
};

/* Information to pass to elf_syminfo.  */

struct elf_syminfo_data
{
  /* Symbols for the next module.  */
  struct elf_syminfo_data *next;
  /* The ELF symbols, sorted by address.  */
  struct elf_symbol *symbols;
  /* The number of symbols.  */
  size_t count;
};

/* Information about PowerPC64 ELFv1 .opd section.  */

struct elf_ppc64_opd_data
{
  /* Address of the .opd section.  */
  b_elf_addr addr;
  /* Section data.  */
  const char *data;
  /* Size of the .opd section.  */
  size_t size;
  /* Corresponding section view.  */
  struct backtrace_view view;
};

/* Compute the CRC-32 of BUF/LEN.  This uses the CRC used for
   .gnu_debuglink files and in xz decoder.  */

static uint32_t
elf_crc32 (uint32_t crc, const unsigned char *buf, size_t len)
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
elf_crc32_file (struct backtrace_state *state, int descriptor,
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

  ret = elf_crc32 (0, (const unsigned char *) file_view.data, st.st_size);

  backtrace_release_view (state, &file_view, error_callback, data);

  return ret;
}

/* Compute the CRC-64 of BUF/LEN.  This uses the CRC in xz decoder.  */

static uint64_t
elf_crc64 (uint64_t crc, const unsigned char *buf, size_t len)
{
  static const uint64_t crc64_table[256] =
    {
      0x0000000000000000UL, 0xb32e4cbe03a75f6fUL, 0xf4843657a840a05bUL, 0x47aa7ae9abe7ff34UL, 0x7bd0c384ff8f5e33UL, 
      0xc8fe8f3afc28015cUL, 0x8f54f5d357cffe68UL, 0x3c7ab96d5468a107UL, 0xf7a18709ff1ebc66UL, 0x448fcbb7fcb9e309UL, 
      0x0325b15e575e1c3dUL, 0xb00bfde054f94352UL, 0x8c71448d0091e255UL, 0x3f5f08330336bd3aUL, 0x78f572daa8d1420eUL, 
      0xcbdb3e64ab761d61UL, 0x7d9ba13851336649UL, 0xceb5ed8652943926UL, 0x891f976ff973c612UL, 0x3a31dbd1fad4997dUL, 
      0x064b62bcaebc387aUL, 0xb5652e02ad1b6715UL, 0xf2cf54eb06fc9821UL, 0x41e11855055bc74eUL, 0x8a3a2631ae2dda2fUL, 
      0x39146a8fad8a8540UL, 0x7ebe1066066d7a74UL, 0xcd905cd805ca251bUL, 0xf1eae5b551a2841cUL, 0x42c4a90b5205db73UL, 
      0x056ed3e2f9e22447UL, 0xb6409f5cfa457b28UL, 0xfb374270a266cc92UL, 0x48190ecea1c193fdUL, 0x0fb374270a266cc9UL, 
      0xbc9d3899098133a6UL, 0x80e781f45de992a1UL, 0x33c9cd4a5e4ecdceUL, 0x7463b7a3f5a932faUL, 0xc74dfb1df60e6d95UL, 
      0x0c96c5795d7870f4UL, 0xbfb889c75edf2f9bUL, 0xf812f32ef538d0afUL, 0x4b3cbf90f69f8fc0UL, 0x774606fda2f72ec7UL, 
      0xc4684a43a15071a8UL, 0x83c230aa0ab78e9cUL, 0x30ec7c140910d1f3UL, 0x86ace348f355aadbUL, 0x3582aff6f0f2f5b4UL, 
      0x7228d51f5b150a80UL, 0xc10699a158b255efUL, 0xfd7c20cc0cdaf4e8UL, 0x4e526c720f7dab87UL, 0x09f8169ba49a54b3UL, 
      0xbad65a25a73d0bdcUL, 0x710d64410c4b16bdUL, 0xc22328ff0fec49d2UL, 0x85895216a40bb6e6UL, 0x36a71ea8a7ace989UL, 
      0x0adda7c5f3c4488eUL, 0xb9f3eb7bf06317e1UL, 0xfe5991925b84e8d5UL, 0x4d77dd2c5823b7baUL, 0x64b62bcaebc387a1UL, 
      0xd7986774e864d8ceUL, 0x90321d9d438327faUL, 0x231c512340247895UL, 0x1f66e84e144cd992UL, 0xac48a4f017eb86fdUL, 
      0xebe2de19bc0c79c9UL, 0x58cc92a7bfab26a6UL, 0x9317acc314dd3bc7UL, 0x2039e07d177a64a8UL, 0x67939a94bc9d9b9cUL, 
      0xd4bdd62abf3ac4f3UL, 0xe8c76f47eb5265f4UL, 0x5be923f9e8f53a9bUL, 0x1c4359104312c5afUL, 0xaf6d15ae40b59ac0UL, 
      0x192d8af2baf0e1e8UL, 0xaa03c64cb957be87UL, 0xeda9bca512b041b3UL, 0x5e87f01b11171edcUL, 0x62fd4976457fbfdbUL, 
      0xd1d305c846d8e0b4UL, 0x96797f21ed3f1f80UL, 0x2557339fee9840efUL, 0xee8c0dfb45ee5d8eUL, 0x5da24145464902e1UL, 
      0x1a083bacedaefdd5UL, 0xa9267712ee09a2baUL, 0x955cce7fba6103bdUL, 0x267282c1b9c65cd2UL, 0x61d8f8281221a3e6UL, 
      0xd2f6b4961186fc89UL, 0x9f8169ba49a54b33UL, 0x2caf25044a02145cUL, 0x6b055fede1e5eb68UL, 0xd82b1353e242b407UL, 
      0xe451aa3eb62a1500UL, 0x577fe680b58d4a6fUL, 0x10d59c691e6ab55bUL, 0xa3fbd0d71dcdea34UL, 0x6820eeb3b6bbf755UL, 
      0xdb0ea20db51ca83aUL, 0x9ca4d8e41efb570eUL, 0x2f8a945a1d5c0861UL, 0x13f02d374934a966UL, 0xa0de61894a93f609UL, 
      0xe7741b60e174093dUL, 0x545a57dee2d35652UL, 0xe21ac88218962d7aUL, 0x5134843c1b317215UL, 0x169efed5b0d68d21UL, 
      0xa5b0b26bb371d24eUL, 0x99ca0b06e7197349UL, 0x2ae447b8e4be2c26UL, 0x6d4e3d514f59d312UL, 0xde6071ef4cfe8c7dUL, 
      0x15bb4f8be788911cUL, 0xa6950335e42fce73UL, 0xe13f79dc4fc83147UL, 0x521135624c6f6e28UL, 0x6e6b8c0f1807cf2fUL, 
      0xdd45c0b11ba09040UL, 0x9aefba58b0476f74UL, 0x29c1f6e6b3e0301bUL, 0xc96c5795d7870f42UL, 0x7a421b2bd420502dUL, 
      0x3de861c27fc7af19UL, 0x8ec62d7c7c60f076UL, 0xb2bc941128085171UL, 0x0192d8af2baf0e1eUL, 0x4638a2468048f12aUL, 
      0xf516eef883efae45UL, 0x3ecdd09c2899b324UL, 0x8de39c222b3eec4bUL, 0xca49e6cb80d9137fUL, 0x7967aa75837e4c10UL, 
      0x451d1318d716ed17UL, 0xf6335fa6d4b1b278UL, 0xb199254f7f564d4cUL, 0x02b769f17cf11223UL, 0xb4f7f6ad86b4690bUL, 
      0x07d9ba1385133664UL, 0x4073c0fa2ef4c950UL, 0xf35d8c442d53963fUL, 0xcf273529793b3738UL, 0x7c0979977a9c6857UL, 
      0x3ba3037ed17b9763UL, 0x888d4fc0d2dcc80cUL, 0x435671a479aad56dUL, 0xf0783d1a7a0d8a02UL, 0xb7d247f3d1ea7536UL, 
      0x04fc0b4dd24d2a59UL, 0x3886b22086258b5eUL, 0x8ba8fe9e8582d431UL, 0xcc0284772e652b05UL, 0x7f2cc8c92dc2746aUL, 
      0x325b15e575e1c3d0UL, 0x8175595b76469cbfUL, 0xc6df23b2dda1638bUL, 0x75f16f0cde063ce4UL, 0x498bd6618a6e9de3UL, 
      0xfaa59adf89c9c28cUL, 0xbd0fe036222e3db8UL, 0x0e21ac88218962d7UL, 0xc5fa92ec8aff7fb6UL, 0x76d4de52895820d9UL, 
      0x317ea4bb22bfdfedUL, 0x8250e80521188082UL, 0xbe2a516875702185UL, 0x0d041dd676d77eeaUL, 0x4aae673fdd3081deUL, 
      0xf9802b81de97deb1UL, 0x4fc0b4dd24d2a599UL, 0xfceef8632775faf6UL, 0xbb44828a8c9205c2UL, 0x086ace348f355aadUL, 
      0x34107759db5dfbaaUL, 0x873e3be7d8faa4c5UL, 0xc094410e731d5bf1UL, 0x73ba0db070ba049eUL, 0xb86133d4dbcc19ffUL, 
      0x0b4f7f6ad86b4690UL, 0x4ce50583738cb9a4UL, 0xffcb493d702be6cbUL, 0xc3b1f050244347ccUL, 0x709fbcee27e418a3UL, 
      0x3735c6078c03e797UL, 0x841b8ab98fa4b8f8UL, 0xadda7c5f3c4488e3UL, 0x1ef430e13fe3d78cUL, 0x595e4a08940428b8UL, 
      0xea7006b697a377d7UL, 0xd60abfdbc3cbd6d0UL, 0x6524f365c06c89bfUL, 0x228e898c6b8b768bUL, 0x91a0c532682c29e4UL, 
      0x5a7bfb56c35a3485UL, 0xe955b7e8c0fd6beaUL, 0xaeffcd016b1a94deUL, 0x1dd181bf68bdcbb1UL, 0x21ab38d23cd56ab6UL, 
      0x9285746c3f7235d9UL, 0xd52f0e859495caedUL, 0x6601423b97329582UL, 0xd041dd676d77eeaaUL, 0x636f91d96ed0b1c5UL, 
      0x24c5eb30c5374ef1UL, 0x97eba78ec690119eUL, 0xab911ee392f8b099UL, 0x18bf525d915feff6UL, 0x5f1528b43ab810c2UL, 
      0xec3b640a391f4fadUL, 0x27e05a6e926952ccUL, 0x94ce16d091ce0da3UL, 0xd3646c393a29f297UL, 0x604a2087398eadf8UL, 
      0x5c3099ea6de60cffUL, 0xef1ed5546e415390UL, 0xa8b4afbdc5a6aca4UL, 0x1b9ae303c601f3cbUL, 0x56ed3e2f9e224471UL, 
      0xe5c372919d851b1eUL, 0xa26908783662e42aUL, 0x114744c635c5bb45UL, 0x2d3dfdab61ad1a42UL, 0x9e13b115620a452dUL, 
      0xd9b9cbfcc9edba19UL, 0x6a978742ca4ae576UL, 0xa14cb926613cf817UL, 0x1262f598629ba778UL, 0x55c88f71c97c584cUL, 
      0xe6e6c3cfcadb0723UL, 0xda9c7aa29eb3a624UL, 0x69b2361c9d14f94bUL, 0x2e184cf536f3067fUL, 0x9d36004b35545910UL, 
      0x2b769f17cf112238UL, 0x9858d3a9ccb67d57UL, 0xdff2a94067518263UL, 0x6cdce5fe64f6dd0cUL, 0x50a65c93309e7c0bUL, 
      0xe388102d33392364UL, 0xa4226ac498dedc50UL, 0x170c267a9b79833fUL, 0xdcd7181e300f9e5eUL, 0x6ff954a033a8c131UL, 
      0x28532e49984f3e05UL, 0x9b7d62f79be8616aUL, 0xa707db9acf80c06dUL, 0x14299724cc279f02UL, 0x5383edcd67c06036UL, 
      0xe0ada17364673f59UL,
    };
  const unsigned char *end;

  crc = ~crc;
  for (end = buf + len; buf < end; ++ buf)
    crc = crc64_table[(crc ^ *buf) & 0xff] ^ (crc >> 8);
  return ~crc;
}

/* A dummy callback function used when we can't find any debug info.  */

static int
elf_nodebug (struct backtrace_state *state ATTRIBUTE_UNUSED,
	     uintptr_t pc ATTRIBUTE_UNUSED,
	     backtrace_full_callback callback ATTRIBUTE_UNUSED,
	     backtrace_error_callback error_callback, void *data)
{
  error_callback (data, "no debug info in ELF executable", -1);
  return 0;
}

/* A dummy callback function used when we can't find a symbol
   table.  */

static void
elf_nosyms (struct backtrace_state *state ATTRIBUTE_UNUSED,
	    uintptr_t addr ATTRIBUTE_UNUSED,
	    backtrace_syminfo_callback callback ATTRIBUTE_UNUSED,
	    backtrace_error_callback error_callback, void *data)
{
  error_callback (data, "no symbol table in ELF executable", -1);
}

/* Compare struct elf_symbol for qsort.  */

static int
elf_symbol_compare (const void *v1, const void *v2)
{
  const struct elf_symbol *e1 = (const struct elf_symbol *) v1;
  const struct elf_symbol *e2 = (const struct elf_symbol *) v2;

  if (e1->address < e2->address)
    return -1;
  else if (e1->address > e2->address)
    return 1;
  else
    return 0;
}

/* Compare an ADDR against an elf_symbol for bsearch.  We allocate one
   extra entry in the array so that this can look safely at the next
   entry.  */

static int
elf_symbol_search (const void *vkey, const void *ventry)
{
  const uintptr_t *key = (const uintptr_t *) vkey;
  const struct elf_symbol *entry = (const struct elf_symbol *) ventry;
  uintptr_t addr;

  addr = *key;
  if (addr < entry->address)
    return -1;
  else if (addr >= entry->address + entry->size)
    return 1;
  else
    return 0;
}

/* Initialize the symbol table info for elf_syminfo.  */

static int
elf_initialize_syminfo (struct backtrace_state *state,
			uintptr_t base_address,
			const unsigned char *symtab_data, size_t symtab_size,
			const unsigned char *strtab, size_t strtab_size,
			backtrace_error_callback error_callback,
			void *data, struct elf_syminfo_data *sdata,
			struct elf_ppc64_opd_data *opd)
{
  size_t sym_count;
  const b_elf_sym *sym;
  size_t elf_symbol_count;
  size_t elf_symbol_size;
  struct elf_symbol *elf_symbols;
  size_t i;
  unsigned int j;

  sym_count = symtab_size / sizeof (b_elf_sym);

  /* We only care about function symbols.  Count them.  */
  sym = (const b_elf_sym *) symtab_data;
  elf_symbol_count = 0;
  for (i = 0; i < sym_count; ++i, ++sym)
    {
      int info;

      info = sym->st_info & 0xf;
      if ((info == STT_FUNC || info == STT_OBJECT)
	  && sym->st_shndx != SHN_UNDEF)
	++elf_symbol_count;
    }

  elf_symbol_size = elf_symbol_count * sizeof (struct elf_symbol);
  elf_symbols = ((struct elf_symbol *)
		 backtrace_alloc (state, elf_symbol_size, error_callback,
				  data));
  if (elf_symbols == NULL)
    return 0;

  sym = (const b_elf_sym *) symtab_data;
  j = 0;
  for (i = 0; i < sym_count; ++i, ++sym)
    {
      int info;

      info = sym->st_info & 0xf;
      if (info != STT_FUNC && info != STT_OBJECT)
	continue;
      if (sym->st_shndx == SHN_UNDEF)
	continue;
      if (sym->st_name >= strtab_size)
	{
	  error_callback (data, "symbol string index out of range", 0);
	  backtrace_free (state, elf_symbols, elf_symbol_size, error_callback,
			  data);
	  return 0;
	}
      elf_symbols[j].name = (const char *) strtab + sym->st_name;
      /* Special case PowerPC64 ELFv1 symbols in .opd section, if the symbol
	 is a function descriptor, read the actual code address from the
	 descriptor.  */
      if (opd
	  && sym->st_value >= opd->addr
	  && sym->st_value < opd->addr + opd->size)
	elf_symbols[j].address
	  = *(const b_elf_addr *) (opd->data + (sym->st_value - opd->addr));
      else
	elf_symbols[j].address = sym->st_value;
      elf_symbols[j].address += base_address;
      elf_symbols[j].size = sym->st_size;
      ++j;
    }

  backtrace_qsort (elf_symbols, elf_symbol_count, sizeof (struct elf_symbol),
		   elf_symbol_compare);

  sdata->next = NULL;
  sdata->symbols = elf_symbols;
  sdata->count = elf_symbol_count;

  return 1;
}

/* Add EDATA to the list in STATE.  */

static void
elf_add_syminfo_data (struct backtrace_state *state,
		      struct elf_syminfo_data *edata)
{
  if (!state->threaded)
    {
      struct elf_syminfo_data **pp;

      for (pp = (struct elf_syminfo_data **) (void *) &state->syminfo_data;
	   *pp != NULL;
	   pp = &(*pp)->next)
	;
      *pp = edata;
    }
  else
    {
      while (1)
	{
	  struct elf_syminfo_data **pp;

	  pp = (struct elf_syminfo_data **) (void *) &state->syminfo_data;

	  while (1)
	    {
	      struct elf_syminfo_data *p;

	      p = backtrace_atomic_load_pointer (pp);

	      if (p == NULL)
		break;

	      pp = &p->next;
	    }

	  if (__sync_bool_compare_and_swap (pp, NULL, edata))
	    break;
	}
    }
}

/* Return the symbol name and value for an ADDR.  */

static void
elf_syminfo (struct backtrace_state *state, uintptr_t addr,
	     backtrace_syminfo_callback callback,
	     backtrace_error_callback error_callback ATTRIBUTE_UNUSED,
	     void *data)
{
  struct elf_syminfo_data *edata;
  struct elf_symbol *sym = NULL;

  if (!state->threaded)
    {
      for (edata = (struct elf_syminfo_data *) state->syminfo_data;
	   edata != NULL;
	   edata = edata->next)
	{
	  sym = ((struct elf_symbol *)
		 bsearch (&addr, edata->symbols, edata->count,
			  sizeof (struct elf_symbol), elf_symbol_search));
	  if (sym != NULL)
	    break;
	}
    }
  else
    {
      struct elf_syminfo_data **pp;

      pp = (struct elf_syminfo_data **) (void *) &state->syminfo_data;
      while (1)
	{
	  edata = backtrace_atomic_load_pointer (pp);
	  if (edata == NULL)
	    break;

	  sym = ((struct elf_symbol *)
		 bsearch (&addr, edata->symbols, edata->count,
			  sizeof (struct elf_symbol), elf_symbol_search));
	  if (sym != NULL)
	    break;

	  pp = &edata->next;
	}
    }

  if (sym == NULL)
    callback (data, addr, NULL, 0, 0);
  else
    callback (data, addr, sym->name, sym->address, sym->size);
}

/* Return whether FILENAME is a symlink.  */

static int
elf_is_symlink (const char *filename)
{
  struct stat st;

  if (lstat (filename, &st) < 0)
    return 0;
  return S_ISLNK (st.st_mode);
}

/* Return the results of reading the symlink FILENAME in a buffer
   allocated by backtrace_alloc.  Return the length of the buffer in
   *LEN.  */

static char *
elf_readlink (struct backtrace_state *state, const char *filename,
	      backtrace_error_callback error_callback, void *data,
	      size_t *plen)
{
  size_t len;
  char *buf;

  len = 128;
  while (1)
    {
      ssize_t rl;

      buf = backtrace_alloc (state, len, error_callback, data);
      if (buf == NULL)
	return NULL;
      rl = readlink (filename, buf, len);
      if (rl < 0)
	{
	  backtrace_free (state, buf, len, error_callback, data);
	  return NULL;
	}
      if ((size_t) rl < len - 1)
	{
	  buf[rl] = '\0';
	  *plen = len;
	  return buf;
	}
      backtrace_free (state, buf, len, error_callback, data);
      len *= 2;
    }
}

#define SYSTEM_BUILD_ID_DIR "/usr/lib/debug/.build-id/"

/* Open a separate debug info file, using the build ID to find it.
   Returns an open file descriptor, or -1.

   The GDB manual says that the only place gdb looks for a debug file
   when the build ID is known is in /usr/lib/debug/.build-id.  */

static int
elf_open_debugfile_by_buildid (struct backtrace_state *state,
			       const char *buildid_data, size_t buildid_size,
			       backtrace_error_callback error_callback,
			       void *data)
{
  const char * const prefix = SYSTEM_BUILD_ID_DIR;
  const size_t prefix_len = strlen (prefix);
  const char * const suffix = ".debug";
  const size_t suffix_len = strlen (suffix);
  size_t len;
  char *bd_filename;
  char *t;
  size_t i;
  int ret;
  int does_not_exist;

  len = prefix_len + buildid_size * 2 + suffix_len + 2;
  bd_filename = backtrace_alloc (state, len, error_callback, data);
  if (bd_filename == NULL)
    return -1;

  t = bd_filename;
  memcpy (t, prefix, prefix_len);
  t += prefix_len;
  for (i = 0; i < buildid_size; i++)
    {
      unsigned char b;
      unsigned char nib;

      b = (unsigned char) buildid_data[i];
      nib = (b & 0xf0) >> 4;
      *t++ = nib < 10 ? '0' + nib : 'a' + nib - 10;
      nib = b & 0x0f;
      *t++ = nib < 10 ? '0' + nib : 'a' + nib - 10;
      if (i == 0)
	*t++ = '/';
    }
  memcpy (t, suffix, suffix_len);
  t[suffix_len] = '\0';

  ret = backtrace_open (bd_filename, error_callback, data, &does_not_exist);

  backtrace_free (state, bd_filename, len, error_callback, data);

  /* gdb checks that the debuginfo file has the same build ID note.
     That seems kind of pointless to me--why would it have the right
     name but not the right build ID?--so skipping the check.  */

  return ret;
}

/* Try to open a file whose name is PREFIX (length PREFIX_LEN)
   concatenated with PREFIX2 (length PREFIX2_LEN) concatenated with
   DEBUGLINK_NAME.  Returns an open file descriptor, or -1.  */

static int
elf_try_debugfile (struct backtrace_state *state, const char *prefix,
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

  backtrace_free (state, try, try_len, error_callback, data);

  return ret;
}

/* Find a separate debug info file, using the debuglink section data
   to find it.  Returns an open file descriptor, or -1.  */

static int
elf_find_debugfile_by_debuglink (struct backtrace_state *state,
				 const char *filename,
				 const char *debuglink_name,
				 backtrace_error_callback error_callback,
				 void *data)
{
  int ret;
  char *alc;
  size_t alc_len;
  const char *slash;
  int ddescriptor;
  const char *prefix;
  size_t prefix_len;

  /* Resolve symlinks in FILENAME.  Since FILENAME is fairly likely to
     be /proc/self/exe, symlinks are common.  We don't try to resolve
     the whole path name, just the base name.  */
  ret = -1;
  alc = NULL;
  alc_len = 0;
  while (elf_is_symlink (filename))
    {
      char *new_buf;
      size_t new_len;

      new_buf = elf_readlink (state, filename, error_callback, data, &new_len);
      if (new_buf == NULL)
	break;

      if (new_buf[0] == '/')
	filename = new_buf;
      else
	{
	  slash = strrchr (filename, '/');
	  if (slash == NULL)
	    filename = new_buf;
	  else
	    {
	      size_t clen;
	      char *c;

	      slash++;
	      clen = slash - filename + strlen (new_buf) + 1;
	      c = backtrace_alloc (state, clen, error_callback, data);
	      if (c == NULL)
		goto done;

	      memcpy (c, filename, slash - filename);
	      memcpy (c + (slash - filename), new_buf, strlen (new_buf));
	      c[slash - filename + strlen (new_buf)] = '\0';
	      backtrace_free (state, new_buf, new_len, error_callback, data);
	      filename = c;
	      new_buf = c;
	      new_len = clen;
	    }
	}

      if (alc != NULL)
	backtrace_free (state, alc, alc_len, error_callback, data);
      alc = new_buf;
      alc_len = new_len;
    }

  /* Look for DEBUGLINK_NAME in the same directory as FILENAME.  */

  slash = strrchr (filename, '/');
  if (slash == NULL)
    {
      prefix = "";
      prefix_len = 0;
    }
  else
    {
      slash++;
      prefix = filename;
      prefix_len = slash - filename;
    }

  ddescriptor = elf_try_debugfile (state, prefix, prefix_len, "", 0,
				   debuglink_name, error_callback, data);
  if (ddescriptor >= 0)
    {
      ret = ddescriptor;
      goto done;
    }

  /* Look for DEBUGLINK_NAME in a .debug subdirectory of FILENAME.  */

  ddescriptor = elf_try_debugfile (state, prefix, prefix_len, ".debug/",
				   strlen (".debug/"), debuglink_name,
				   error_callback, data);
  if (ddescriptor >= 0)
    {
      ret = ddescriptor;
      goto done;
    }

  /* Look for DEBUGLINK_NAME in /usr/lib/debug.  */

  ddescriptor = elf_try_debugfile (state, "/usr/lib/debug/",
				   strlen ("/usr/lib/debug/"), prefix,
				   prefix_len, debuglink_name,
				   error_callback, data);
  if (ddescriptor >= 0)
    ret = ddescriptor;

 done:
  if (alc != NULL && alc_len > 0)
    backtrace_free (state, alc, alc_len, error_callback, data);
  return ret;
}

/* Open a separate debug info file, using the debuglink section data
   to find it.  Returns an open file descriptor, or -1.  */

static int
elf_open_debugfile_by_debuglink (struct backtrace_state *state,
				 const char *filename,
				 const char *debuglink_name,
				 uint32_t debuglink_crc,
				 backtrace_error_callback error_callback,
				 void *data)
{
  int ddescriptor;

  ddescriptor = elf_find_debugfile_by_debuglink (state, filename,
						 debuglink_name,
						 error_callback, data);
  if (ddescriptor < 0)
    return -1;

  if (debuglink_crc != 0)
    {
      uint32_t got_crc;

      got_crc = elf_crc32_file (state, ddescriptor, error_callback, data);
      if (got_crc != debuglink_crc)
	{
	  backtrace_close (ddescriptor, error_callback, data);
	  return -1;
	}
    }

  return ddescriptor;
}

/* A function useful for setting a breakpoint for an inflation failure
   when this code is compiled with -g.  */

static void
elf_zlib_failed(void)
{
}

/* *PVAL is the current value being read from the stream, and *PBITS
   is the number of valid bits.  Ensure that *PVAL holds at least 15
   bits by reading additional bits from *PPIN, up to PINEND, as
   needed.  Updates *PPIN, *PVAL and *PBITS.  Returns 1 on success, 0
   on error.  */

static int
elf_zlib_fetch (const unsigned char **ppin, const unsigned char *pinend,
		uint64_t *pval, unsigned int *pbits)
{
  unsigned int bits;
  const unsigned char *pin;
  uint64_t val;
  uint32_t next;

  bits = *pbits;
  if (bits >= 15)
    return 1;
  pin = *ppin;
  val = *pval;

  if (unlikely (pinend - pin < 4))
    {
      elf_zlib_failed ();
      return 0;
    }

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) \
    && defined(__ORDER_BIG_ENDIAN__) \
    && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ \
        || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  /* We've ensured that PIN is aligned.  */
  next = *(const uint32_t *)pin;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  next = __builtin_bswap32 (next);
#endif
#else
  next = pin[0] | (pin[1] << 8) | (pin[2] << 16) | (pin[3] << 24);
#endif

  val |= (uint64_t)next << bits;
  bits += 32;
  pin += 4;

  /* We will need the next four bytes soon.  */
  __builtin_prefetch (pin, 0, 0);

  *ppin = pin;
  *pval = val;
  *pbits = bits;
  return 1;
}

/* Huffman code tables, like the rest of the zlib format, are defined
   by RFC 1951.  We store a Huffman code table as a series of tables
   stored sequentially in memory.  Each entry in a table is 16 bits.
   The first, main, table has 256 entries.  It is followed by a set of
   secondary tables of length 2 to 128 entries.  The maximum length of
   a code sequence in the deflate format is 15 bits, so that is all we
   need.  Each secondary table has an index, which is the offset of
   the table in the overall memory storage.

   The deflate format says that all codes of a given bit length are
   lexicographically consecutive.  Perhaps we could have 130 values
   that require a 15-bit code, perhaps requiring three secondary
   tables of size 128.  I don't know if this is actually possible, but
   it suggests that the maximum size required for secondary tables is
   3 * 128 + 3 * 64 ... == 768.  The zlib enough program reports 660
   as the maximum.  We permit 768, since in addition to the 256 for
   the primary table, with two bytes per entry, and with the two
   tables we need, that gives us a page.

   A single table entry needs to store a value or (for the main table
   only) the index and size of a secondary table.  Values range from 0
   to 285, inclusive.  Secondary table indexes, per above, range from
   0 to 510.  For a value we need to store the number of bits we need
   to determine that value (one value may appear multiple times in the
   table), which is 1 to 8.  For a secondary table we need to store
   the number of bits used to index into the table, which is 1 to 7.
   And of course we need 1 bit to decide whether we have a value or a
   secondary table index.  So each entry needs 9 bits for value/table
   index, 3 bits for size, 1 bit what it is.  For simplicity we use 16
   bits per entry.  */

/* Number of entries we allocate to for one code table.  We get a page
   for the two code tables we need.  */

#define HUFFMAN_TABLE_SIZE (1024)

/* Bit masks and shifts for the values in the table.  */

#define HUFFMAN_VALUE_MASK 0x01ff
#define HUFFMAN_BITS_SHIFT 9
#define HUFFMAN_BITS_MASK 0x7
#define HUFFMAN_SECONDARY_SHIFT 12

/* For working memory while inflating we need two code tables, we need
   an array of code lengths (max value 15, so we use unsigned char),
   and an array of unsigned shorts used while building a table.  The
   latter two arrays must be large enough to hold the maximum number
   of code lengths, which RFC 1951 defines as 286 + 30.  */

#define ZDEBUG_TABLE_SIZE \
  (2 * HUFFMAN_TABLE_SIZE * sizeof (uint16_t) \
   + (286 + 30) * sizeof (uint16_t)	      \
   + (286 + 30) * sizeof (unsigned char))

#define ZDEBUG_TABLE_CODELEN_OFFSET \
  (2 * HUFFMAN_TABLE_SIZE * sizeof (uint16_t) \
   + (286 + 30) * sizeof (uint16_t))

#define ZDEBUG_TABLE_WORK_OFFSET \
  (2 * HUFFMAN_TABLE_SIZE * sizeof (uint16_t))

#ifdef BACKTRACE_GENERATE_FIXED_HUFFMAN_TABLE

/* Used by the main function that generates the fixed table to learn
   the table size.  */
static size_t final_next_secondary;

#endif

/* Build a Huffman code table from an array of lengths in CODES of
   length CODES_LEN.  The table is stored into *TABLE.  ZDEBUG_TABLE
   is the same as for elf_zlib_inflate, used to find some work space.
   Returns 1 on success, 0 on error.  */

static int
elf_zlib_inflate_table (unsigned char *codes, size_t codes_len,
			uint16_t *zdebug_table, uint16_t *table)
{
  uint16_t count[16];
  uint16_t start[16];
  uint16_t prev[16];
  uint16_t firstcode[7];
  uint16_t *next;
  size_t i;
  size_t j;
  unsigned int code;
  size_t next_secondary;

  /* Count the number of code of each length.  Set NEXT[val] to be the
     next value after VAL with the same bit length.  */

  next = (uint16_t *) (((unsigned char *) zdebug_table)
		       + ZDEBUG_TABLE_WORK_OFFSET);

  memset (&count[0], 0, 16 * sizeof (uint16_t));
  for (i = 0; i < codes_len; ++i)
    {
      if (unlikely (codes[i] >= 16))
	{
	  elf_zlib_failed ();
	  return 0;
	}

      if (count[codes[i]] == 0)
	{
	  start[codes[i]] = i;
	  prev[codes[i]] = i;
	}
      else
	{
	  next[prev[codes[i]]] = i;
	  prev[codes[i]] = i;
	}

      ++count[codes[i]];
    }

  /* For each length, fill in the table for the codes of that
     length.  */

  memset (table, 0, HUFFMAN_TABLE_SIZE * sizeof (uint16_t));

  /* Handle the values that do not require a secondary table.  */

  code = 0;
  for (j = 1; j <= 8; ++j)
    {
      unsigned int jcnt;
      unsigned int val;

      jcnt = count[j];
      if (jcnt == 0)
	continue;

      if (unlikely (jcnt > (1U << j)))
	{
	  elf_zlib_failed ();
	  return 0;
	}

      /* There are JCNT values that have this length, the values
	 starting from START[j] continuing through NEXT[VAL].  Those
	 values are assigned consecutive values starting at CODE.  */

      val = start[j];
      for (i = 0; i < jcnt; ++i)
	{
	  uint16_t tval;
	  size_t ind;
	  unsigned int incr;

	  /* In the compressed bit stream, the value VAL is encoded as
	     J bits with the value C.  */

	  if (unlikely ((val & ~HUFFMAN_VALUE_MASK) != 0))
	    {
	      elf_zlib_failed ();
	      return 0;
	    }

	  tval = val | ((j - 1) << HUFFMAN_BITS_SHIFT);

	  /* The table lookup uses 8 bits.  If J is less than 8, we
	     don't know what the other bits will be.  We need to fill
	     in all possibilities in the table.  Since the Huffman
	     code is unambiguous, those entries can't be used for any
	     other code.  */

	  for (ind = code; ind < 0x100; ind += 1 << j)
	    {
	      if (unlikely (table[ind] != 0))
		{
		  elf_zlib_failed ();
		  return 0;
		}
	      table[ind] = tval;
	    }

	  /* Advance to the next value with this length.  */
	  if (i + 1 < jcnt)
	    val = next[val];

	  /* The Huffman codes are stored in the bitstream with the
	     most significant bit first, as is required to make them
	     unambiguous.  The effect is that when we read them from
	     the bitstream we see the bit sequence in reverse order:
	     the most significant bit of the Huffman code is the least
	     significant bit of the value we read from the bitstream.
	     That means that to make our table lookups work, we need
	     to reverse the bits of CODE.  Since reversing bits is
	     tedious and in general requires using a table, we instead
	     increment CODE in reverse order.  That is, if the number
	     of bits we are currently using, here named J, is 3, we
	     count as 000, 100, 010, 110, 001, 101, 011, 111, which is
	     to say the numbers from 0 to 7 but with the bits
	     reversed.  Going to more bits, aka incrementing J,
	     effectively just adds more zero bits as the beginning,
	     and as such does not change the numeric value of CODE.

	     To increment CODE of length J in reverse order, find the
	     most significant zero bit and set it to one while
	     clearing all higher bits.  In other words, add 1 modulo
	     2^J, only reversed.  */

	  incr = 1U << (j - 1);
	  while ((code & incr) != 0)
	    incr >>= 1;
	  if (incr == 0)
	    code = 0;
	  else
	    {
	      code &= incr - 1;
	      code += incr;
	    }
	}
    }

  /* Handle the values that require a secondary table.  */

  /* Set FIRSTCODE, the number at which the codes start, for each
     length.  */

  for (j = 9; j < 16; j++)
    {
      unsigned int jcnt;
      unsigned int k;

      jcnt = count[j];
      if (jcnt == 0)
	continue;

      /* There are JCNT values that have this length, the values
	 starting from START[j].  Those values are assigned
	 consecutive values starting at CODE.  */

      firstcode[j - 9] = code;

      /* Reverse add JCNT to CODE modulo 2^J.  */
      for (k = 0; k < j; ++k)
	{
	  if ((jcnt & (1U << k)) != 0)
	    {
	      unsigned int m;
	      unsigned int bit;

	      bit = 1U << (j - k - 1);
	      for (m = 0; m < j - k; ++m, bit >>= 1)
		{
		  if ((code & bit) == 0)
		    {
		      code += bit;
		      break;
		    }
		  code &= ~bit;
		}
	      jcnt &= ~(1U << k);
	    }
	}
      if (unlikely (jcnt != 0))
	{
	  elf_zlib_failed ();
	  return 0;
	}
    }

  /* For J from 9 to 15, inclusive, we store COUNT[J] consecutive
     values starting at START[J] with consecutive codes starting at
     FIRSTCODE[J - 9].  In the primary table we need to point to the
     secondary table, and the secondary table will be indexed by J - 9
     bits.  We count down from 15 so that we install the larger
     secondary tables first, as the smaller ones may be embedded in
     the larger ones.  */

  next_secondary = 0; /* Index of next secondary table (after primary).  */
  for (j = 15; j >= 9; j--)
    {
      unsigned int jcnt;
      unsigned int val;
      size_t primary; /* Current primary index.  */
      size_t secondary; /* Offset to current secondary table.  */
      size_t secondary_bits; /* Bit size of current secondary table.  */

      jcnt = count[j];
      if (jcnt == 0)
	continue;

      val = start[j];
      code = firstcode[j - 9];
      primary = 0x100;
      secondary = 0;
      secondary_bits = 0;
      for (i = 0; i < jcnt; ++i)
	{
	  uint16_t tval;
	  size_t ind;
	  unsigned int incr;

	  if ((code & 0xff) != primary)
	    {
	      uint16_t tprimary;

	      /* Fill in a new primary table entry.  */

	      primary = code & 0xff;

	      tprimary = table[primary];
	      if (tprimary == 0)
		{
		  /* Start a new secondary table.  */

		  if (unlikely ((next_secondary & HUFFMAN_VALUE_MASK)
				!= next_secondary))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }

		  secondary = next_secondary;
		  secondary_bits = j - 8;
		  next_secondary += 1 << secondary_bits;
		  table[primary] = (secondary
				    + ((j - 8) << HUFFMAN_BITS_SHIFT)
				    + (1U << HUFFMAN_SECONDARY_SHIFT));
		}
	      else
		{
		  /* There is an existing entry.  It had better be a
		     secondary table with enough bits.  */
		  if (unlikely ((tprimary & (1U << HUFFMAN_SECONDARY_SHIFT))
				== 0))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }
		  secondary = tprimary & HUFFMAN_VALUE_MASK;
		  secondary_bits = ((tprimary >> HUFFMAN_BITS_SHIFT)
				    & HUFFMAN_BITS_MASK);
		  if (unlikely (secondary_bits < j - 8))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }
		}
	    }

	  /* Fill in secondary table entries.  */

	  tval = val | ((j - 8) << HUFFMAN_BITS_SHIFT);

	  for (ind = code >> 8;
	       ind < (1U << secondary_bits);
	       ind += 1U << (j - 8))
	    {
	      if (unlikely (table[secondary + 0x100 + ind] != 0))
		{
		  elf_zlib_failed ();
		  return 0;
		}
	      table[secondary + 0x100 + ind] = tval;
	    }

	  if (i + 1 < jcnt)
	    val = next[val];

	  incr = 1U << (j - 1);
	  while ((code & incr) != 0)
	    incr >>= 1;
	  if (incr == 0)
	    code = 0;
	  else
	    {
	      code &= incr - 1;
	      code += incr;
	    }
	}
    }

#ifdef BACKTRACE_GENERATE_FIXED_HUFFMAN_TABLE
  final_next_secondary = next_secondary;
#endif

  return 1;
}

#ifdef BACKTRACE_GENERATE_FIXED_HUFFMAN_TABLE

/* Used to generate the fixed Huffman table for block type 1.  */

#include <stdio.h>

static uint16_t table[ZDEBUG_TABLE_SIZE];
static unsigned char codes[288];

int
main ()
{
  size_t i;

  for (i = 0; i <= 143; ++i)
    codes[i] = 8;
  for (i = 144; i <= 255; ++i)
    codes[i] = 9;
  for (i = 256; i <= 279; ++i)
    codes[i] = 7;
  for (i = 280; i <= 287; ++i)
    codes[i] = 8;
  if (!elf_zlib_inflate_table (&codes[0], 288, &table[0], &table[0]))
    {
      fprintf (stderr, "elf_zlib_inflate_table failed\n");
      exit (EXIT_FAILURE);
    }

  printf ("static const uint16_t elf_zlib_default_table[%#zx] =\n",
	  final_next_secondary + 0x100);
  printf ("{\n");
  for (i = 0; i < final_next_secondary + 0x100; i += 8)
    {
      size_t j;

      printf (" ");
      for (j = i; j < final_next_secondary + 0x100 && j < i + 8; ++j)
	printf (" %#x,", table[j]);
      printf ("\n");
    }
  printf ("};\n");
  printf ("\n");

  for (i = 0; i < 32; ++i)
    codes[i] = 5;
  if (!elf_zlib_inflate_table (&codes[0], 32, &table[0], &table[0]))
    {
      fprintf (stderr, "elf_zlib_inflate_table failed\n");
      exit (EXIT_FAILURE);
    }

  printf ("static const uint16_t elf_zlib_default_dist_table[%#zx] =\n",
	  final_next_secondary + 0x100);
  printf ("{\n");
  for (i = 0; i < final_next_secondary + 0x100; i += 8)
    {
      size_t j;

      printf (" ");
      for (j = i; j < final_next_secondary + 0x100 && j < i + 8; ++j)
	printf (" %#x,", table[j]);
      printf ("\n");
    }
  printf ("};\n");

  return 0;
}

#endif

/* The fixed tables generated by the #ifdef'ed out main function
   above.  */

static const uint16_t elf_zlib_default_table[0x170] =
{
  0xd00, 0xe50, 0xe10, 0xf18, 0xd10, 0xe70, 0xe30, 0x1230,
  0xd08, 0xe60, 0xe20, 0x1210, 0xe00, 0xe80, 0xe40, 0x1250,
  0xd04, 0xe58, 0xe18, 0x1200, 0xd14, 0xe78, 0xe38, 0x1240,
  0xd0c, 0xe68, 0xe28, 0x1220, 0xe08, 0xe88, 0xe48, 0x1260,
  0xd02, 0xe54, 0xe14, 0xf1c, 0xd12, 0xe74, 0xe34, 0x1238,
  0xd0a, 0xe64, 0xe24, 0x1218, 0xe04, 0xe84, 0xe44, 0x1258,
  0xd06, 0xe5c, 0xe1c, 0x1208, 0xd16, 0xe7c, 0xe3c, 0x1248,
  0xd0e, 0xe6c, 0xe2c, 0x1228, 0xe0c, 0xe8c, 0xe4c, 0x1268,
  0xd01, 0xe52, 0xe12, 0xf1a, 0xd11, 0xe72, 0xe32, 0x1234,
  0xd09, 0xe62, 0xe22, 0x1214, 0xe02, 0xe82, 0xe42, 0x1254,
  0xd05, 0xe5a, 0xe1a, 0x1204, 0xd15, 0xe7a, 0xe3a, 0x1244,
  0xd0d, 0xe6a, 0xe2a, 0x1224, 0xe0a, 0xe8a, 0xe4a, 0x1264,
  0xd03, 0xe56, 0xe16, 0xf1e, 0xd13, 0xe76, 0xe36, 0x123c,
  0xd0b, 0xe66, 0xe26, 0x121c, 0xe06, 0xe86, 0xe46, 0x125c,
  0xd07, 0xe5e, 0xe1e, 0x120c, 0xd17, 0xe7e, 0xe3e, 0x124c,
  0xd0f, 0xe6e, 0xe2e, 0x122c, 0xe0e, 0xe8e, 0xe4e, 0x126c,
  0xd00, 0xe51, 0xe11, 0xf19, 0xd10, 0xe71, 0xe31, 0x1232,
  0xd08, 0xe61, 0xe21, 0x1212, 0xe01, 0xe81, 0xe41, 0x1252,
  0xd04, 0xe59, 0xe19, 0x1202, 0xd14, 0xe79, 0xe39, 0x1242,
  0xd0c, 0xe69, 0xe29, 0x1222, 0xe09, 0xe89, 0xe49, 0x1262,
  0xd02, 0xe55, 0xe15, 0xf1d, 0xd12, 0xe75, 0xe35, 0x123a,
  0xd0a, 0xe65, 0xe25, 0x121a, 0xe05, 0xe85, 0xe45, 0x125a,
  0xd06, 0xe5d, 0xe1d, 0x120a, 0xd16, 0xe7d, 0xe3d, 0x124a,
  0xd0e, 0xe6d, 0xe2d, 0x122a, 0xe0d, 0xe8d, 0xe4d, 0x126a,
  0xd01, 0xe53, 0xe13, 0xf1b, 0xd11, 0xe73, 0xe33, 0x1236,
  0xd09, 0xe63, 0xe23, 0x1216, 0xe03, 0xe83, 0xe43, 0x1256,
  0xd05, 0xe5b, 0xe1b, 0x1206, 0xd15, 0xe7b, 0xe3b, 0x1246,
  0xd0d, 0xe6b, 0xe2b, 0x1226, 0xe0b, 0xe8b, 0xe4b, 0x1266,
  0xd03, 0xe57, 0xe17, 0xf1f, 0xd13, 0xe77, 0xe37, 0x123e,
  0xd0b, 0xe67, 0xe27, 0x121e, 0xe07, 0xe87, 0xe47, 0x125e,
  0xd07, 0xe5f, 0xe1f, 0x120e, 0xd17, 0xe7f, 0xe3f, 0x124e,
  0xd0f, 0xe6f, 0xe2f, 0x122e, 0xe0f, 0xe8f, 0xe4f, 0x126e,
  0x290, 0x291, 0x292, 0x293, 0x294, 0x295, 0x296, 0x297,
  0x298, 0x299, 0x29a, 0x29b, 0x29c, 0x29d, 0x29e, 0x29f,
  0x2a0, 0x2a1, 0x2a2, 0x2a3, 0x2a4, 0x2a5, 0x2a6, 0x2a7,
  0x2a8, 0x2a9, 0x2aa, 0x2ab, 0x2ac, 0x2ad, 0x2ae, 0x2af,
  0x2b0, 0x2b1, 0x2b2, 0x2b3, 0x2b4, 0x2b5, 0x2b6, 0x2b7,
  0x2b8, 0x2b9, 0x2ba, 0x2bb, 0x2bc, 0x2bd, 0x2be, 0x2bf,
  0x2c0, 0x2c1, 0x2c2, 0x2c3, 0x2c4, 0x2c5, 0x2c6, 0x2c7,
  0x2c8, 0x2c9, 0x2ca, 0x2cb, 0x2cc, 0x2cd, 0x2ce, 0x2cf,
  0x2d0, 0x2d1, 0x2d2, 0x2d3, 0x2d4, 0x2d5, 0x2d6, 0x2d7,
  0x2d8, 0x2d9, 0x2da, 0x2db, 0x2dc, 0x2dd, 0x2de, 0x2df,
  0x2e0, 0x2e1, 0x2e2, 0x2e3, 0x2e4, 0x2e5, 0x2e6, 0x2e7,
  0x2e8, 0x2e9, 0x2ea, 0x2eb, 0x2ec, 0x2ed, 0x2ee, 0x2ef,
  0x2f0, 0x2f1, 0x2f2, 0x2f3, 0x2f4, 0x2f5, 0x2f6, 0x2f7,
  0x2f8, 0x2f9, 0x2fa, 0x2fb, 0x2fc, 0x2fd, 0x2fe, 0x2ff,
};

static const uint16_t elf_zlib_default_dist_table[0x100] =
{
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
  0x800, 0x810, 0x808, 0x818, 0x804, 0x814, 0x80c, 0x81c,
  0x802, 0x812, 0x80a, 0x81a, 0x806, 0x816, 0x80e, 0x81e,
  0x801, 0x811, 0x809, 0x819, 0x805, 0x815, 0x80d, 0x81d,
  0x803, 0x813, 0x80b, 0x81b, 0x807, 0x817, 0x80f, 0x81f,
};

/* Inflate a zlib stream from PIN/SIN to POUT/SOUT.  Return 1 on
   success, 0 on some error parsing the stream.  */

static int
elf_zlib_inflate (const unsigned char *pin, size_t sin, uint16_t *zdebug_table,
		  unsigned char *pout, size_t sout)
{
  unsigned char *porigout;
  const unsigned char *pinend;
  unsigned char *poutend;

  /* We can apparently see multiple zlib streams concatenated
     together, so keep going as long as there is something to read.
     The last 4 bytes are the checksum.  */
  porigout = pout;
  pinend = pin + sin;
  poutend = pout + sout;
  while ((pinend - pin) > 4)
    {
      uint64_t val;
      unsigned int bits;
      int last;

      /* Read the two byte zlib header.  */

      if (unlikely ((pin[0] & 0xf) != 8)) /* 8 is zlib encoding.  */
	{
	  /* Unknown compression method.  */
	  elf_zlib_failed ();
	  return 0;
	}
      if (unlikely ((pin[0] >> 4) > 7))
	{
	  /* Window size too large.  Other than this check, we don't
	     care about the window size.  */
	  elf_zlib_failed ();
	  return 0;
	}
      if (unlikely ((pin[1] & 0x20) != 0))
	{
	  /* Stream expects a predefined dictionary, but we have no
	     dictionary.  */
	  elf_zlib_failed ();
	  return 0;
	}
      val = (pin[0] << 8) | pin[1];
      if (unlikely (val % 31 != 0))
	{
	  /* Header check failure.  */
	  elf_zlib_failed ();
	  return 0;
	}
      pin += 2;

      /* Align PIN to a 32-bit boundary.  */

      val = 0;
      bits = 0;
      while ((((uintptr_t) pin) & 3) != 0)
	{
	  val |= (uint64_t)*pin << bits;
	  bits += 8;
	  ++pin;
	}

      /* Read blocks until one is marked last.  */

      last = 0;

      while (!last)
	{
	  unsigned int type;
	  const uint16_t *tlit;
	  const uint16_t *tdist;

	  if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
	    return 0;

	  last = val & 1;
	  type = (val >> 1) & 3;
	  val >>= 3;
	  bits -= 3;

	  if (unlikely (type == 3))
	    {
	      /* Invalid block type.  */
	      elf_zlib_failed ();
	      return 0;
	    }

	  if (type == 0)
	    {
	      uint16_t len;
	      uint16_t lenc;

	      /* An uncompressed block.  */

	      /* If we've read ahead more than a byte, back up.  */
	      while (bits > 8)
		{
		  --pin;
		  bits -= 8;
		}

	      val = 0;
	      bits = 0;
	      if (unlikely ((pinend - pin) < 4))
		{
		  /* Missing length.  */
		  elf_zlib_failed ();
		  return 0;
		}
	      len = pin[0] | (pin[1] << 8);
	      lenc = pin[2] | (pin[3] << 8);
	      pin += 4;
	      lenc = ~lenc;
	      if (unlikely (len != lenc))
		{
		  /* Corrupt data.  */
		  elf_zlib_failed ();
		  return 0;
		}
	      if (unlikely (len > (unsigned int) (pinend - pin)
			    || len > (unsigned int) (poutend - pout)))
		{
		  /* Not enough space in buffers.  */
		  elf_zlib_failed ();
		  return 0;
		}
	      memcpy (pout, pin, len);
	      pout += len;
	      pin += len;

	      /* Align PIN.  */
	      while ((((uintptr_t) pin) & 3) != 0)
		{
		  val |= (uint64_t)*pin << bits;
		  bits += 8;
		  ++pin;
		}

	      /* Go around to read the next block.  */
	      continue;
	    }

	  if (type == 1)
	    {
	      tlit = elf_zlib_default_table;
	      tdist = elf_zlib_default_dist_table;
	    }
	  else
	    {
	      unsigned int nlit;
	      unsigned int ndist;
	      unsigned int nclen;
	      unsigned char codebits[19];
	      unsigned char *plenbase;
	      unsigned char *plen;
	      unsigned char *plenend;

	      /* Read a Huffman encoding table.  The various magic
		 numbers here are from RFC 1951.  */

	      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		return 0;

	      nlit = (val & 0x1f) + 257;
	      val >>= 5;
	      ndist = (val & 0x1f) + 1;
	      val >>= 5;
	      nclen = (val & 0xf) + 4;
	      val >>= 4;
	      bits -= 14;
	      if (unlikely (nlit > 286 || ndist > 30))
		{
		  /* Values out of range.  */
		  elf_zlib_failed ();
		  return 0;
		}

	      /* Read and build the table used to compress the
		 literal, length, and distance codes.  */

	      memset(&codebits[0], 0, 19);

	      /* There are always at least 4 elements in the
		 table.  */

	      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		return 0;

	      codebits[16] = val & 7;
	      codebits[17] = (val >> 3) & 7;
	      codebits[18] = (val >> 6) & 7;
	      codebits[0] = (val >> 9) & 7;
	      val >>= 12;
	      bits -= 12;

	      if (nclen == 4)
		goto codebitsdone;

	      codebits[8] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 5)
		goto codebitsdone;

	      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		return 0;

	      codebits[7] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 6)
		goto codebitsdone;

	      codebits[9] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 7)
		goto codebitsdone;

	      codebits[6] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 8)
		goto codebitsdone;

	      codebits[10] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 9)
		goto codebitsdone;

	      codebits[5] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 10)
		goto codebitsdone;

	      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		return 0;

	      codebits[11] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 11)
		goto codebitsdone;

	      codebits[4] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 12)
		goto codebitsdone;

	      codebits[12] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 13)
		goto codebitsdone;

	      codebits[3] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 14)
		goto codebitsdone;

	      codebits[13] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 15)
		goto codebitsdone;

	      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		return 0;

	      codebits[2] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 16)
		goto codebitsdone;

	      codebits[14] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 17)
		goto codebitsdone;

	      codebits[1] = val & 7;
	      val >>= 3;
	      bits -= 3;

	      if (nclen == 18)
		goto codebitsdone;

	      codebits[15] = val & 7;
	      val >>= 3;
	      bits -= 3;

	    codebitsdone:

	      if (!elf_zlib_inflate_table (codebits, 19, zdebug_table,
					   zdebug_table))
		return 0;

	      /* Read the compressed bit lengths of the literal,
		 length, and distance codes.  We have allocated space
		 at the end of zdebug_table to hold them.  */

	      plenbase = (((unsigned char *) zdebug_table)
			  + ZDEBUG_TABLE_CODELEN_OFFSET);
	      plen = plenbase;
	      plenend = plen + nlit + ndist;
	      while (plen < plenend)
		{
		  uint16_t t;
		  unsigned int b;
		  uint16_t v;

		  if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		    return 0;

		  t = zdebug_table[val & 0xff];

		  /* The compression here uses bit lengths up to 7, so
		     a secondary table is never necessary.  */
		  if (unlikely ((t & (1U << HUFFMAN_SECONDARY_SHIFT)) != 0))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }

		  b = (t >> HUFFMAN_BITS_SHIFT) & HUFFMAN_BITS_MASK;
		  val >>= b + 1;
		  bits -= b + 1;

		  v = t & HUFFMAN_VALUE_MASK;
		  if (v < 16)
		    *plen++ = v;
		  else if (v == 16)
		    {
		      unsigned int c;
		      unsigned int prev;

		      /* Copy previous entry 3 to 6 times.  */

		      if (unlikely (plen == plenbase))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      /* We used up to 7 bits since the last
			 elf_zlib_fetch, so we have at least 8 bits
			 available here.  */

		      c = 3 + (val & 0x3);
		      val >>= 2;
		      bits -= 2;
		      if (unlikely ((unsigned int) (plenend - plen) < c))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      prev = plen[-1];
		      switch (c)
			{
			case 6:
			  *plen++ = prev;
			  /* fallthrough */
			case 5:
			  *plen++ = prev;
			  /* fallthrough */
			case 4:
			  *plen++ = prev;
			}
		      *plen++ = prev;
		      *plen++ = prev;
		      *plen++ = prev;
		    }
		  else if (v == 17)
		    {
		      unsigned int c;

		      /* Store zero 3 to 10 times.  */

		      /* We used up to 7 bits since the last
			 elf_zlib_fetch, so we have at least 8 bits
			 available here.  */

		      c = 3 + (val & 0x7);
		      val >>= 3;
		      bits -= 3;
		      if (unlikely ((unsigned int) (plenend - plen) < c))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      switch (c)
			{
			case 10:
			  *plen++ = 0;
			  /* fallthrough */
			case 9:
			  *plen++ = 0;
			  /* fallthrough */
			case 8:
			  *plen++ = 0;
			  /* fallthrough */
			case 7:
			  *plen++ = 0;
			  /* fallthrough */
			case 6:
			  *plen++ = 0;
			  /* fallthrough */
			case 5:
			  *plen++ = 0;
			  /* fallthrough */
			case 4:
			  *plen++ = 0;
			}
		      *plen++ = 0;
		      *plen++ = 0;
		      *plen++ = 0;
		    }
		  else if (v == 18)
		    {
		      unsigned int c;

		      /* Store zero 11 to 138 times.  */

		      /* We used up to 7 bits since the last
			 elf_zlib_fetch, so we have at least 8 bits
			 available here.  */

		      c = 11 + (val & 0x7f);
		      val >>= 7;
		      bits -= 7;
		      if (unlikely ((unsigned int) (plenend - plen) < c))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      memset (plen, 0, c);
		      plen += c;
		    }
		  else
		    {
		      elf_zlib_failed ();
		      return 0;
		    }
		}

	      /* Make sure that the stop code can appear.  */

	      plen = plenbase;
	      if (unlikely (plen[256] == 0))
		{
		  elf_zlib_failed ();
		  return 0;
		}

	      /* Build the decompression tables.  */

	      if (!elf_zlib_inflate_table (plen, nlit, zdebug_table,
					   zdebug_table))
		return 0;
	      if (!elf_zlib_inflate_table (plen + nlit, ndist, zdebug_table,
					   zdebug_table + HUFFMAN_TABLE_SIZE))
		return 0;
	      tlit = zdebug_table;
	      tdist = zdebug_table + HUFFMAN_TABLE_SIZE;
	    }

	  /* Inflate values until the end of the block.  This is the
	     main loop of the inflation code.  */

	  while (1)
	    {
	      uint16_t t;
	      unsigned int b;
	      uint16_t v;
	      unsigned int lit;

	      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		return 0;

	      t = tlit[val & 0xff];
	      b = (t >> HUFFMAN_BITS_SHIFT) & HUFFMAN_BITS_MASK;
	      v = t & HUFFMAN_VALUE_MASK;

	      if ((t & (1U << HUFFMAN_SECONDARY_SHIFT)) == 0)
		{
		  lit = v;
		  val >>= b + 1;
		  bits -= b + 1;
		}
	      else
		{
		  t = tlit[v + 0x100 + ((val >> 8) & ((1U << b) - 1))];
		  b = (t >> HUFFMAN_BITS_SHIFT) & HUFFMAN_BITS_MASK;
		  lit = t & HUFFMAN_VALUE_MASK;
		  val >>= b + 8;
		  bits -= b + 8;
		}

	      if (lit < 256)
		{
		  if (unlikely (pout == poutend))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }

		  *pout++ = lit;

		  /* We will need to write the next byte soon.  We ask
		     for high temporal locality because we will write
		     to the whole cache line soon.  */
		  __builtin_prefetch (pout, 1, 3);
		}
	      else if (lit == 256)
		{
		  /* The end of the block.  */
		  break;
		}
	      else
		{
		  unsigned int dist;
		  unsigned int len;

		  /* Convert lit into a length.  */

		  if (lit < 265)
		    len = lit - 257 + 3;
		  else if (lit == 285)
		    len = 258;
		  else if (unlikely (lit > 285))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }
		  else
		    {
		      unsigned int extra;

		      if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
			return 0;

		      /* This is an expression for the table of length
			 codes in RFC 1951 3.2.5.  */
		      lit -= 265;
		      extra = (lit >> 2) + 1;
		      len = (lit & 3) << extra;
		      len += 11;
		      len += ((1U << (extra - 1)) - 1) << 3;
		      len += val & ((1U << extra) - 1);
		      val >>= extra;
		      bits -= extra;
		    }

		  if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
		    return 0;

		  t = tdist[val & 0xff];
		  b = (t >> HUFFMAN_BITS_SHIFT) & HUFFMAN_BITS_MASK;
		  v = t & HUFFMAN_VALUE_MASK;

		  if ((t & (1U << HUFFMAN_SECONDARY_SHIFT)) == 0)
		    {
		      dist = v;
		      val >>= b + 1;
		      bits -= b + 1;
		    }
		  else
		    {
		      t = tdist[v + 0x100 + ((val >> 8) & ((1U << b) - 1))];
		      b = (t >> HUFFMAN_BITS_SHIFT) & HUFFMAN_BITS_MASK;
		      dist = t & HUFFMAN_VALUE_MASK;
		      val >>= b + 8;
		      bits -= b + 8;
		    }

		  /* Convert dist to a distance.  */

		  if (dist == 0)
		    {
		      /* A distance of 1.  A common case, meaning
			 repeat the last character LEN times.  */

		      if (unlikely (pout == porigout))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      if (unlikely ((unsigned int) (poutend - pout) < len))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      memset (pout, pout[-1], len);
		      pout += len;
		    }
		  else if (unlikely (dist > 29))
		    {
		      elf_zlib_failed ();
		      return 0;
		    }
		  else
		    {
		      if (dist < 4)
			dist = dist + 1;
		      else
			{
			  unsigned int extra;

			  if (!elf_zlib_fetch (&pin, pinend, &val, &bits))
			    return 0;

			  /* This is an expression for the table of
			     distance codes in RFC 1951 3.2.5.  */
			  dist -= 4;
			  extra = (dist >> 1) + 1;
			  dist = (dist & 1) << extra;
			  dist += 5;
			  dist += ((1U << (extra - 1)) - 1) << 2;
			  dist += val & ((1U << extra) - 1);
			  val >>= extra;
			  bits -= extra;
			}

		      /* Go back dist bytes, and copy len bytes from
			 there.  */

		      if (unlikely ((unsigned int) (pout - porigout) < dist))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      if (unlikely ((unsigned int) (poutend - pout) < len))
			{
			  elf_zlib_failed ();
			  return 0;
			}

		      if (dist >= len)
			{
			  memcpy (pout, pout - dist, len);
			  pout += len;
			}
		      else
			{
			  while (len > 0)
			    {
			      unsigned int copy;

			      copy = len < dist ? len : dist;
			      memcpy (pout, pout - dist, copy);
			      len -= copy;
			      pout += copy;
			    }
			}
		    }
		}
	    }
	}
    }

  /* We should have filled the output buffer.  */
  if (unlikely (pout != poutend))
    {
      elf_zlib_failed ();
      return 0;
    }

  return 1;
}

/* Verify the zlib checksum.  The checksum is in the 4 bytes at
   CHECKBYTES, and the uncompressed data is at UNCOMPRESSED /
   UNCOMPRESSED_SIZE.  Returns 1 on success, 0 on failure.  */

static int
elf_zlib_verify_checksum (const unsigned char *checkbytes,
			  const unsigned char *uncompressed,
			  size_t uncompressed_size)
{
  unsigned int i;
  unsigned int cksum;
  const unsigned char *p;
  uint32_t s1;
  uint32_t s2;
  size_t hsz;

  cksum = 0;
  for (i = 0; i < 4; i++)
    cksum = (cksum << 8) | checkbytes[i];

  s1 = 1;
  s2 = 0;

  /* Minimize modulo operations.  */

  p = uncompressed;
  hsz = uncompressed_size;
  while (hsz >= 5552)
    {
      for (i = 0; i < 5552; i += 16)
	{
	  /* Manually unroll loop 16 times.  */
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	  s1 = s1 + *p++;
	  s2 = s2 + s1;
	}
      hsz -= 5552;
      s1 %= 65521;
      s2 %= 65521;
    }

  while (hsz >= 16)
    {
      /* Manually unroll loop 16 times.  */
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;
      s1 = s1 + *p++;
      s2 = s2 + s1;

      hsz -= 16;
    }

  for (i = 0; i < hsz; ++i)
    {
      s1 = s1 + *p++;
      s2 = s2 + s1;
    }

  s1 %= 65521;
  s2 %= 65521;

  if (unlikely ((s2 << 16) + s1 != cksum))
    {
      elf_zlib_failed ();
      return 0;
    }

  return 1;
}

/* Inflate a zlib stream from PIN/SIN to POUT/SOUT, and verify the
   checksum.  Return 1 on success, 0 on error.  */

static int
elf_zlib_inflate_and_verify (const unsigned char *pin, size_t sin,
			     uint16_t *zdebug_table, unsigned char *pout,
			     size_t sout)
{
  if (!elf_zlib_inflate (pin, sin, zdebug_table, pout, sout))
    return 0;
  if (!elf_zlib_verify_checksum (pin + sin - 4, pout, sout))
    return 0;
  return 1;
}

/* Uncompress the old compressed debug format, the one emitted by
   --compress-debug-sections=zlib-gnu.  The compressed data is in
   COMPRESSED / COMPRESSED_SIZE, and the function writes to
   *UNCOMPRESSED / *UNCOMPRESSED_SIZE.  ZDEBUG_TABLE is work space to
   hold Huffman tables.  Returns 0 on error, 1 on successful
   decompression or if something goes wrong.  In general we try to
   carry on, by returning 1, even if we can't decompress.  */

static int
elf_uncompress_zdebug (struct backtrace_state *state,
		       const unsigned char *compressed, size_t compressed_size,
		       uint16_t *zdebug_table,
		       backtrace_error_callback error_callback, void *data,
		       unsigned char **uncompressed, size_t *uncompressed_size)
{
  size_t sz;
  size_t i;
  unsigned char *po;

  *uncompressed = NULL;
  *uncompressed_size = 0;

  /* The format starts with the four bytes ZLIB, followed by the 8
     byte length of the uncompressed data in big-endian order,
     followed by a zlib stream.  */

  if (compressed_size < 12 || memcmp (compressed, "ZLIB", 4) != 0)
    return 1;

  sz = 0;
  for (i = 0; i < 8; i++)
    sz = (sz << 8) | compressed[i + 4];

  if (*uncompressed != NULL && *uncompressed_size >= sz)
    po = *uncompressed;
  else
    {
      po = (unsigned char *) backtrace_alloc (state, sz, error_callback, data);
      if (po == NULL)
	return 0;
    }

  if (!elf_zlib_inflate_and_verify (compressed + 12, compressed_size - 12,
				    zdebug_table, po, sz))
    return 1;

  *uncompressed = po;
  *uncompressed_size = sz;

  return 1;
}

/* Uncompress the new compressed debug format, the official standard
   ELF approach emitted by --compress-debug-sections=zlib-gabi.  The
   compressed data is in COMPRESSED / COMPRESSED_SIZE, and the
   function writes to *UNCOMPRESSED / *UNCOMPRESSED_SIZE.
   ZDEBUG_TABLE is work space as for elf_uncompress_zdebug.  Returns 0
   on error, 1 on successful decompression or if something goes wrong.
   In general we try to carry on, by returning 1, even if we can't
   decompress.  */

static int
elf_uncompress_chdr (struct backtrace_state *state,
		     const unsigned char *compressed, size_t compressed_size,
		     uint16_t *zdebug_table,
		     backtrace_error_callback error_callback, void *data,
		     unsigned char **uncompressed, size_t *uncompressed_size)
{
  const b_elf_chdr *chdr;
  unsigned char *po;

  *uncompressed = NULL;
  *uncompressed_size = 0;

  /* The format starts with an ELF compression header.  */
  if (compressed_size < sizeof (b_elf_chdr))
    return 1;

  chdr = (const b_elf_chdr *) compressed;

  if (chdr->ch_type != ELFCOMPRESS_ZLIB)
    {
      /* Unsupported compression algorithm.  */
      return 1;
    }

  if (*uncompressed != NULL && *uncompressed_size >= chdr->ch_size)
    po = *uncompressed;
  else
    {
      po = (unsigned char *) backtrace_alloc (state, chdr->ch_size,
					      error_callback, data);
      if (po == NULL)
	return 0;
    }

  if (!elf_zlib_inflate_and_verify (compressed + sizeof (b_elf_chdr),
				    compressed_size - sizeof (b_elf_chdr),
				    zdebug_table, po, chdr->ch_size))
    return 1;

  *uncompressed = po;
  *uncompressed_size = chdr->ch_size;

  return 1;
}

/* This function is a hook for testing the zlib support.  It is only
   used by tests.  */

int
backtrace_uncompress_zdebug (struct backtrace_state *state,
			     const unsigned char *compressed,
			     size_t compressed_size,
			     backtrace_error_callback error_callback,
			     void *data, unsigned char **uncompressed,
			     size_t *uncompressed_size)
{
  uint16_t *zdebug_table;
  int ret;

  zdebug_table = ((uint16_t *) backtrace_alloc (state, ZDEBUG_TABLE_SIZE,
						error_callback, data));
  if (zdebug_table == NULL)
    return 0;
  ret = elf_uncompress_zdebug (state, compressed, compressed_size,
			       zdebug_table, error_callback, data,
			       uncompressed, uncompressed_size);
  backtrace_free (state, zdebug_table, ZDEBUG_TABLE_SIZE,
		  error_callback, data);
  return ret;
}

#ifdef MINI_DEBUG_INFO

/* Inline functions to access unaligned unsigned 32-bit integers */
static inline uint32_t get_unaligned_le32(const uint8_t *buf)
{
  return (uint32_t)buf[0]
		  | ((uint32_t)buf[1] << 8)
		  | ((uint32_t)buf[2] << 16)
		  | ((uint32_t)buf[3] << 24);
}

static inline uint32_t get_unaligned_be32(const uint8_t *buf)
{
  return (uint32_t)(buf[0] << 24)
		  | ((uint32_t)buf[1] << 16)
		  | ((uint32_t)buf[2] << 8)
		  | (uint32_t)buf[3];
}

static inline void put_unaligned_le32(uint32_t val, uint8_t *buf)
{
  buf[0] = (uint8_t)val;
  buf[1] = (uint8_t)(val >> 8);
  buf[2] = (uint8_t)(val >> 16);
  buf[3] = (uint8_t)(val >> 24);
}

static inline void put_unaligned_be32(uint32_t val, uint8_t *buf)
{
  buf[0] = (uint8_t)(val >> 24);
  buf[1] = (uint8_t)(val >> 16);
  buf[2] = (uint8_t)(val >> 8);
  buf[3] = (uint8_t)val;
}

/*
 * Use get_unaligned_le32() also for aligned access for simplicity. On
 * little endian systems, #define get_le32(ptr) (*(const uint32_t *)(ptr))
 * could save a few bytes in code size.
 */
#ifndef get_le32
  #define get_le32 get_unaligned_le32
#endif

/* Range coder constants */
#define LZMA_RC_SHIFT_BITS 8
#define LZMA_RC_TOP_BITS 24
#define LZMA_RC_TOP_VALUE (1 << LZMA_RC_TOP_BITS)
#define LZMA_RC_BIT_MODEL_TOTAL_BITS 11
#define LZMA_RC_BIT_MODEL_TOTAL (1 << LZMA_RC_BIT_MODEL_TOTAL_BITS)
#define LZMA_RC_MOVE_BITS 5

/*
 * Maximum number of position states. A position state is the lowest pb
 * number of bits of the current uncompressed offset. In some places there
 * are different sets of probabilities for different position states.
 */
#define LZMA_POS_STATES_MAX (1 << 4)

/*
 * This enum is used to track which LZMA symbols have occurred most recently
 * and in which order. This information is used to predict the next symbol.
 *
 * Symbols:
 *  - Literal: One 8-bit byte
 *  - Match: Repeat a chunk of data at some distance
 *  - Long repeat: Multi-byte match at a recently seen distance
 *  - Short repeat: One-byte repeat at a recently seen distance
 *
 * The symbol names are in from STATE_oldest_older_previous. REP means
 * either short or long repeated match, and NONLIT means any non-literal.
 */
enum lzma_state {
  STATE_LIT_LIT,
  STATE_MATCH_LIT_LIT,
  STATE_REP_LIT_LIT,
  STATE_SHORTREP_LIT_LIT,
  STATE_MATCH_LIT,
  STATE_REP_LIT,
  STATE_SHORTREP_LIT,
  STATE_LIT_MATCH,
  STATE_LIT_LONGREP,
  STATE_LIT_SHORTREP,
  STATE_NONLIT_MATCH,
  STATE_NONLIT_REP
};

/* Total number of states */
#define LZMA_STATES 12

/* The lowest 7 states indicate that the previous state was a literal. */
#define LZMA_LIT_STATES 7

/* Indicate that the latest symbol was a literal. */
static inline void 
lzma_state_literal(enum lzma_state *state)
{
  if (*state <= STATE_SHORTREP_LIT_LIT)
      *state = STATE_LIT_LIT;
  else if (*state <= STATE_LIT_SHORTREP)
      *state -= 3;
  else
      *state -= 6;
}

/* Indicate that the latest symbol was a match. */
static inline void 
lzma_state_match(enum lzma_state *state)
{
  *state = *state < LZMA_LIT_STATES ? STATE_LIT_MATCH : STATE_NONLIT_MATCH;
}

/* Indicate that the latest state was a long repeated match. */
static inline void 
lzma_state_long_rep(enum lzma_state *state)
{
  *state = *state < LZMA_LIT_STATES ? STATE_LIT_LONGREP : STATE_NONLIT_REP;
}

/* Indicate that the latest symbol was a short match. */
static inline void 
lzma_state_short_rep(enum lzma_state *state)
{
  *state = *state < LZMA_LIT_STATES ? STATE_LIT_SHORTREP : STATE_NONLIT_REP;
}

/* Test if the previous symbol was a literal. */
static inline uint8_t 
lzma_state_is_literal(enum lzma_state state)
{
  return state < LZMA_LIT_STATES;
}

/* Each literal coder is divided in three sections:
 *   - 0x001-0x0FF: Without match byte
 *   - 0x101-0x1FF: With match byte; match bit is 0
 *   - 0x201-0x2FF: With match byte; match bit is 1
 *
 * Match byte is used when the previous LZMA symbol was something else than
 * a literal (that is, it was some kind of match).
 */
#define LZMA_LITERAL_CODER_SIZE 0x300

/* Maximum number of literal coders */
#define LZMA_LITERAL_CODERS_MAX (1 << 4)

/* Minimum length of a match is two bytes. */
#define LZMA_MATCH_LEN_MIN 2

/* Match length is encoded with 4, 5, or 10 bits.
 *
 * Length   Bits
 *  2-9      4 = Choice=0 + 3 bits
 * 10-17     5 = Choice=1 + Choice2=0 + 3 bits
 * 18-273   10 = Choice=1 + Choice2=1 + 8 bits
 */
#define LZMA_LEN_LOW_BITS 3
#define LZMA_LEN_LOW_SYMBOLS (1 << LZMA_LEN_LOW_BITS)
#define LZMA_LEN_MID_BITS 3
#define LZMA_LEN_MID_SYMBOLS (1 << LZMA_LEN_MID_BITS)
#define LZMA_LEN_HIGH_BITS 8
#define LZMA_LEN_HIGH_SYMBOLS (1 << LZMA_LEN_HIGH_BITS)
#define LZMA_LEN_SYMBOLS (LZMA_LEN_LOW_SYMBOLS + LZMA_LEN_MID_SYMBOLS + LZMA_LEN_HIGH_SYMBOLS)

/*
 * Maximum length of a match is 273 which is a result of the encoding
 * described above.
 */
#define MATCH_LEN_MAX (LZMA_MATCH_LEN_MIN + LZMA_LEN_SYMBOLS - 1)

/*
 * Different sets of probabilities are used for match distances that have
 * very short match length: Lengths of 2, 3, and 4 bytes have a separate
 * set of probabilities for each length. The matches with longer length
 * use a shared set of probabilities.
 */
#define LZMA_DIST_STATES 4

/*
 * Get the index of the appropriate probability array for decoding
 * the distance slot.
 */
static inline uint32_t 
lzma_get_dist_state(uint32_t len)
{
  return len < LZMA_DIST_STATES + LZMA_MATCH_LEN_MIN?
	 len - LZMA_MATCH_LEN_MIN : LZMA_DIST_STATES - 1;
}

/*
 * The highest two bits of a 32-bit match distance are encoded using six bits.
 * This six-bit value is called a distance slot. This way encoding a 32-bit
 * value takes 6-36 bits, larger values taking more bits.
 */
#define LZMA_DIST_SLOT_BITS 6
#define LZMA_DIST_SLOTS (1 << LZMA_DIST_SLOT_BITS)

/* Match distances up to 127 are fully encoded using probabilities. Since
 * the highest two bits (distance slot) are always encoded using six bits,
 * the distances 0-3 don't need any additional bits to encode, since the
 * distance slot itself is the same as the actual distance. DIST_MODEL_START
 * indicates the first distance slot where at least one additional bit is
 * needed.
 */
#define LZMA_DIST_MODEL_START 4

/*
 * Match distances greater than 127 are encoded in three pieces:
 *   - distance slot: the highest two bits
 *   - direct bits: 2-26 bits below the highest two bits
 *   - alignment bits: four lowest bits
 *
 * Direct bits don't use any probabilities.
 *
 * The distance slot value of 14 is for distances 128-191.
 */
#define LZMA_DIST_MODEL_END 14

/* Distance slots that indicate a distance <= 127. */
#define LZMA_FULL_DISTANCES_BITS (LZMA_DIST_MODEL_END / 2)
#define LZMA_FULL_DISTANCES (1 << LZMA_FULL_DISTANCES_BITS)

/*
 * For match distances greater than 127, only the highest two bits and the
 * lowest four bits (alignment) is encoded using probabilities.
 */
#define LZMA_ALIGN_BITS 4
#define LZMA_ALIGN_SIZE (1 << LZMA_ALIGN_BITS)
#define LZMA_ALIGN_MASK (LZMA_ALIGN_SIZE - 1)

/* Total number of all probability variables */
#define LZMA_PROBS_TOTAL (1846 + LZMA_LITERAL_CODERS_MAX * LZMA_LITERAL_CODER_SIZE)

/*
 * Range decoder initialization eats the first five bytes of each LZMA chunk.
 */
#define LZMA_RC_INIT_BYTES 5

/*
 * Minimum number of usable input buffer to safely decode one LZMA symbol.
 * The worst case is that we decode 22 bits using probabilities and 26
 * direct bits. This may decode at maximum of 20 bytes of input. However,
 * xz_lzma_main() does an extra normalization before returning, thus we
 * need to put 21 here.
 */
#define LZMA_IN_REQUIRED 21

/*
 * Dictionary (history buffer)
 *
 * These are always true:
 *    start <= pos <= full <= size
 *    pos <= limit <= size
 *    size <= size_max
 *    allocated <= size
 *
 */
struct xz_dictionary 
{
  /* Beginning of the history buffer */
  uint8_t *buf;

  /* Old position in buf (before decoding more data) */
  size_t start;

  /* Position in buf */
  size_t pos;

  /*
    * How full dictionary is. This is used to detect corrupt input that
    * would read beyond the beginning of the uncompressed stream.
    */
  size_t full;

  /* Write limit; we don't write to buf[limit] or later bytes. */
  size_t limit;

  /*
    * Size of the dictionary as specified in Block Header. This is used
    * together with "full" to detect corrupt input that would make us
    * read beyond the beginning of the uncompressed stream.
    */
  uint32_t size;

  /*
    * Maximum allowed dictionary size.
    */
  uint32_t size_max;

  /*
    * Amount of memory currently allocated for the dictionary.
    */
  uint32_t allocated;
};

/* Range decoder */
struct xz_rc_dec 
{
  uint32_t range;
  uint32_t code;

  /*
    * Number of initializing bytes remaining to be read
    * by xz_rc_read_init().
    */
  uint32_t init_bytes_left;

  /*
    * Buffer from which we read our input. It can be either
    * temp.buf or the caller-provided input buffer.
    */
  const uint8_t *in;
  size_t in_pos;
  size_t in_limit;
};

/* Probabilities for a length decoder. */
struct xz_lzma_len_dec 
{
  /* Probability of match length being at least 10 */
  uint16_t choice;

  /* Probability of match length being at least 18 */
  uint16_t choice2;

  /* Probabilities for match lengths 2-9 */
  uint16_t low[LZMA_POS_STATES_MAX][LZMA_LEN_LOW_SYMBOLS];

  /* Probabilities for match lengths 10-17 */
  uint16_t mid[LZMA_POS_STATES_MAX][LZMA_LEN_MID_SYMBOLS];

  /* Probabilities for match lengths 18-273 */
  uint16_t high[LZMA_LEN_HIGH_SYMBOLS];
};

struct lzma_dec 
{
  /* Distances of latest four matches */
  uint32_t rep0;
  uint32_t rep1;
  uint32_t rep2;
  uint32_t rep3;

  /* Types of the most recently seen LZMA symbols */
  enum lzma_state state;

  /*
    * Length of a match. This is updated so that xz_dict_repeat can
    * be called again to finish repeating the whole match.
    */
  uint32_t len;

  /*
    * LZMA properties or related bit masks (number of literal
    * context bits, a mask dervied from the number of literal
    * position bits, and a mask dervied from the number
    * position bits)
    */
  uint32_t lc;
  uint32_t literal_pos_mask; /* (1 << lp) - 1 */
  uint32_t pos_mask;         /* (1 << pb) - 1 */

  /* If 1, it's a match. Otherwise it's a single 8-bit literal. */
  uint16_t is_match[LZMA_STATES][LZMA_POS_STATES_MAX];

  /* If 1, it's a repeated match. The distance is one of rep0 .. rep3. */
  uint16_t is_rep[LZMA_STATES];

  /*
    * If 0, distance of a repeated match is rep0.
    * Otherwise check is_rep1.
    */
  uint16_t is_rep0[LZMA_STATES];

  /*
    * If 0, distance of a repeated match is rep1.
    * Otherwise check is_rep2.
    */
  uint16_t is_rep1[LZMA_STATES];

  /* If 0, distance of a repeated match is rep2. Otherwise it is rep3. */
  uint16_t is_rep2[LZMA_STATES];

  /*
    * If 1, the repeated match has length of one byte. Otherwise
    * the length is decoded from rep_len_decoder.
    */
  uint16_t is_rep0_long[LZMA_STATES][LZMA_POS_STATES_MAX];

  /*
    * Probability tree for the highest two bits of the match
    * distance. There is a separate probability tree for match
    * lengths of 2 (i.e. MATCH_LEN_MIN), 3, 4, and [5, 273].
    */
  uint16_t dist_slot[LZMA_DIST_STATES][LZMA_DIST_SLOTS];

  /*
    * Probility trees for additional bits for match distance
    * when the distance is in the range [4, 127].
    */
  uint16_t dist_special[LZMA_FULL_DISTANCES - LZMA_DIST_MODEL_END];

  /*
    * Probability tree for the lowest four bits of a match
    * distance that is equal to or greater than 128.
    */
  uint16_t dist_align[LZMA_ALIGN_SIZE];

  /* Length of a normal match */
  struct xz_lzma_len_dec match_len_dec;

  /* Length of a repeated match */
  struct xz_lzma_len_dec rep_len_dec;

  /* Probabilities of literals */
  uint16_t literal[LZMA_LITERAL_CODERS_MAX][LZMA_LITERAL_CODER_SIZE];
};

struct lzma2_dec {
  /* Position in xz_dec_lzma2_run(). */
  enum lzma2_seq 
    {
      SEQ_CONTROL,
      SEQ_UNCOMPRESSED_1,
      SEQ_UNCOMPRESSED_2,
      SEQ_COMPRESSED_0,
      SEQ_COMPRESSED_1,
      SEQ_PROPERTIES,
      SEQ_LZMA_PREPARE,
      SEQ_LZMA_RUN,
      SEQ_COPY
    } sequence;

  /* Next position after decoding the compressed size of the chunk. */
  enum lzma2_seq next_sequence;

  /* Uncompressed size of LZMA chunk (2 MiB at maximum) */
  uint32_t uncompressed;

  /*
    * Compressed size of LZMA chunk or compressed/uncompressed
    * size of uncompressed chunk (64 KiB at maximum)
    */
  uint32_t compressed;

  /*
    * 1 if dictionary reset is needed. This is 0 before
    * the first chunk (LZMA or uncompressed).
    */
  int need_xz_dict_reset;

  /*
    * 1 if new LZMA properties are needed. This is 0
    * before the first LZMA chunk.
    */
  int need_props;
};

struct xz_dec_lzma2 
{
  /*
    * The order below is important on x86 to reduce code size and
    * it shouldn't hurt on other platforms. Everything up to and
    * including lzma.pos_mask are in the first 128 bytes on x86-32,
    * which allows using smaller instructions to access those
    * variables. On x86-64, fewer variables fit into the first 128
    * bytes, but this is still the best order without sacrificing
    * the readability by splitting the structures.
    */
  struct xz_rc_dec rc;
  struct xz_dictionary dict;
  struct lzma2_dec lzma2;
  struct lzma_dec lzma;

  /*
    * Temporary buffer which holds small number of input bytes between
    * decoder calls. See xz_lzma2_lzma() for details.
    */
  struct 
    {
      uint32_t size;
      uint8_t buf[3 * LZMA_IN_REQUIRED];
    } temp;
    
  struct backtrace_state *state;
  backtrace_error_callback error_callback;
  void *data;
};

/**
 * enum xz_ret - Return codes
 * @XZ_OK:                  Everything is OK so far. More input or more
 *                          output space is required to continue. 
 * @XZ_STREAM_END:          Operation finished successfully.
 * @XZ_UNSUPPORTED_CHECK:   Integrity check type is not supported. Decoding
 *                          is still possible by simply calling xz_dec_run() again.
 *                        
 * @XZ_MEM_ERROR:           Allocating memory failed. The amount of memory that was
 *                          tried to be allocated was no more than the
 *                          xz_dict_max argument given to xz_dec_init().
 * @XZ_MEMLIMIT_ERROR:      A bigger LZMA2 dictionary would be needed than
 *                          allowed by the xz_dict_max argument given to
 *                          xz_dec_init(). 
 * @XZ_FORMAT_ERROR:        File format was not recognized (wrong magic
 *                          bytes).
 * @XZ_OPTIONS_ERROR:       This implementation doesn't support the requested
 *                          compression options. In the decoder this means
 *                          that the header CRC32 matches, but the header
 *                          itself specifies something that we don't support.
 * @XZ_DATA_ERROR:          Compressed data is corrupt.
 * @XZ_BUF_ERROR:           Cannot make any progress. Returned when two consecutive calls
 *                          to XZ code cannot consume any input and cannot produce any new output.
 *                          This happens when there is no new input available, or the output buffer
 *                          is full while at least one output byte is still pending. Assuming your
 *                          code is not buggy, you can get this error only when decoding a compressed
 *                          stream that is truncated or otherwise corrupt.
 */

enum xz_ret {
  XZ_OK,
  XZ_STREAM_END,
  XZ_UNSUPPORTED_CHECK,
  XZ_MEM_ERROR,
  XZ_MEMLIMIT_ERROR,
  XZ_FORMAT_ERROR,
  XZ_OPTIONS_ERROR,
  XZ_DATA_ERROR,
  XZ_BUF_ERROR
};

struct xz_dec_bcj 
{
  /* Type of the BCJ filter being used */
  enum 
    {
      BCJ_X86 = 4,        /* x86 or x86-64 */
      BCJ_POWERPC = 5,    /* Big endian only */
      BCJ_IA64 = 6,       /* Big or little endian */
      BCJ_ARM = 7,        /* Little endian only */
      BCJ_ARMTHUMB = 8,   /* Little endian only */
      BCJ_SPARC = 9       /* Big or little endian */
    } type;

  /*
    * Return value of the next filter in the chain. We need to preserve
    * this information across calls, because we must not call the next
    * filter anymore once it has returned XZ_STREAM_END.
    */
  enum xz_ret ret;

  /*
    * Absolute position relative to the beginning of the uncompressed
    * data (in a single .xz Block). We care only about the lowest 32
    * bits so this doesn't need to be uint64_t even with big files.
    */
  uint32_t pos;

  /* x86 filter state */
  uint32_t x86_prev_mask;

  /* Temporary space to hold the variables from struct xz_buf */
  uint8_t *out;
  size_t out_pos;
  size_t out_size;

  struct 
    {
      /* Amount of already filtered data in the beginning of buf */
      size_t filtered;

      /* Total amount of data currently stored in buf  */
      size_t size;

      /*
      * Buffer to hold a mix of filtered and unfiltered data. This
      * needs to be big enough to hold Alignment + 2 * Look-ahead:
      *
      * Type         Alignment   Look-ahead
      * x86              1           4
      * PowerPC          4           0
      * IA-64           16           0
      * ARM              4           0
      * ARM-Thumb        2           2
      * SPARC            4           0
      */
      uint8_t buf[16];
    } temp;
};

/*
 * See the .xz file format specification at
 * http://tukaani.org/xz/xz-file-format.txt
 * to understand the container format.
 */
#define XZ_STREAM_HEADER_SIZE 12
#define XZ_HEADER_MAGIC "\3757zXZ"
#define XZ_HEADER_MAGIC_SIZE 6
#define XZ_FOOTER_MAGIC "YZ"
#define XZ_FOOTER_MAGIC_SIZE 2

/*
 * Variable-length integer can hold a 63-bit unsigned integer or a special
 * value indicating that the value is unknown.
 *
 * Experimental: xz_vli_type can be defined to uint32_t to save a few bytes
 * in code size (no effect on speed). Doing so limits the uncompressed and
 * compressed size of the file to less than 256 MiB and may also weaken
 * error detection slightly.
 */
typedef uint64_t xz_vli_type;

#define VLI_MAX ((xz_vli_type)-1 / 2)
#define VLI_UNKNOWN ((xz_vli_type)-1)

/* Maximum encoded size of a VLI */
#define VLI_BYTES_MAX (sizeof(xz_vli_type) * 8 / 7)

/* Integrity Check types */
enum xz_check 
{
  XZ_CHECK_NONE = 0,
  XZ_CHECK_CRC32 = 1,
  XZ_CHECK_CRC64 = 4,
  XZ_CHECK_SHA256 = 10
};

/* Maximum possible Check ID */
#define XZ_CHECK_MAX 15

struct xz_dec_hash 
{
  xz_vli_type unpadded;
  xz_vli_type uncompressed;
  uint32_t crc32;
};

/**
 * struct xz_buf - Passing input and output buffers to XZ code
 * @in:         Beginning of the input buffer. This may be NULL if and only
 *              if in_pos is equal to in_size.
 * @in_pos:     Current position in the input buffer. This must not exceed
 *              in_size.
 * @in_size:    Size of the input buffer
 * @out:        Beginning of the output buffer. This may be NULL if and only
 *              if out_pos is equal to out_size.
 * @out_pos:    Current position in the output buffer. This must not exceed
 *              out_size.
 * @out_size:   Size of the output buffer
 *
 * Only the contents of the output buffer from out[out_pos] onward, and
 * the variables in_pos and out_pos are modified by the XZ code.
 */

struct xz_buf 
{
  const uint8_t *in;
  size_t in_pos;
  size_t in_size;

  uint8_t *out;
  size_t out_pos;
  size_t out_size;
};

struct xz_dec 
{
  /* Position in xz_dec_main() */
  enum 
    {
      SEQ_STREAM_HEADER,
      SEQ_BLOCK_START,
      SEQ_BLOCK_HEADER,
      SEQ_BLOCK_UNCOMPRESS,
      SEQ_BLOCK_PADDING,
      SEQ_BLOCK_CHECK,
      SEQ_INDEX,
      SEQ_INDEX_PADDING,
      SEQ_INDEX_CRC32,
      SEQ_STREAM_FOOTER
    } sequence;

  /* Position in variable-length integers and Check fields */
  uint32_t pos;

  /* Variable-length integer decoded by xz_dec_vli() */
  xz_vli_type vli;

  /* Saved in_pos and out_pos */
  size_t in_start;
  size_t out_start;

  /* CRC32 or CRC64 value in Block or CRC32 value in Index */
  uint64_t crc;

  /* Type of the integrity check calculated from uncompressed data */
  enum xz_check check_type;

  /*
    * True if the next call to xz_dec_run() is allowed to return
    * XZ_BUF_ERROR.
    */
  uint8_t allow_buf_error;

  /* Information stored in Block Header */
  struct 
    {
      /*
	* Value stored in the Compressed Size field, or
	* VLI_UNKNOWN if Compressed Size is not present.
	*/
      xz_vli_type compressed;

      /*
	* Value stored in the Uncompressed Size field, or
	* VLI_UNKNOWN if Uncompressed Size is not present.
	*/
      xz_vli_type uncompressed;

      /* Size of the Block Header field */
      uint32_t size;
    } block_header;

  /* Information collected when decoding Blocks */
  struct 
    {
      /* Observed compressed size of the current Block */
      xz_vli_type compressed;

      /* Observed uncompressed size of the current Block */
      xz_vli_type uncompressed;

      /* Number of Blocks decoded so far */
      xz_vli_type count;

      /*
	* Hash calculated from the Block sizes. This is used to
	* validate the Index field.
	*/
      struct xz_dec_hash hash;
    } block;

  /* Variables needed when verifying the Index field */
  struct 
    {
      /* Position in xz_dec_index() */
      enum 
	{
	  SEQ_INDEX_COUNT,
	  SEQ_INDEX_UNPADDED,
	  SEQ_INDEX_UNCOMPRESSED
	} sequence;

      /* Size of the Index in bytes */
      xz_vli_type size;

      /* Number of Records (matches block.count in valid files) */
      xz_vli_type count;

      /*
	* Hash calculated from the Records (matches block.hash in
	* valid files).
	*/
      struct xz_dec_hash hash;
    } index;

  /*
    * Temporary buffer needed to hold Stream Header, Block Header,
    * and Stream Footer. The Block Header is the biggest (1 KiB)
    * so we reserve space according to that. buf[] has to be aligned
    * to a multiple of four bytes; the size_t variables before it
    * should guarantee this.
    */
  struct 
    {
      size_t pos;
      size_t size;
      uint8_t buf[1024];
    } temp;

  struct xz_dec_lzma2 lzma2;

  struct xz_dec_bcj bcj;
  uint8_t bcj_active;
};

/*
 * This is used to test the most significant byte of a memory address
 * in an x86 instruction.
 */
static inline int xz_bcj_x86_test_msbyte(uint8_t b)
{
  return b == 0x00 || b == 0xFF;
}

static size_t 
xz_bcj_x86(struct xz_dec_bcj *s, uint8_t *buf, size_t size)
{
  static const uint8_t mask_to_allowed_status[8] = { 1, 1, 1, 0, 1, 0, 0, 0 };
  static const uint8_t mask_to_bit_num[8] = { 0, 1, 2, 2, 3, 3, 3, 3 };
  size_t i;
  size_t prev_pos;
  uint32_t prev_mask;
  uint32_t src;
  uint32_t dest;
  uint32_t j;
  uint8_t b;

  prev_pos = (size_t)-1;
  prev_mask = s->x86_prev_mask;
  
  if (size <= 4)
    return 0;

  size -= 4;
  for (i = 0; i < size; ++i) 
    {
      if ((buf[i] & 0xFE) != 0xE8)
	continue;

      prev_pos = i - prev_pos;
      if (prev_pos > 3) 
	{
	  prev_mask = 0;
	} 
      else 
	{
	  prev_mask = (prev_mask << (prev_pos - 1)) & 7;
	  if (prev_mask != 0) 
	    {
	      b = buf[i + 4 - mask_to_bit_num[prev_mask]];
	      if (!mask_to_allowed_status[prev_mask]
		  || xz_bcj_x86_test_msbyte(b)) 
		{
		  prev_pos = i;
		  prev_mask = (prev_mask << 1) | 1;
		  continue;
		}
	  }
      }

      prev_pos = i;

      if (xz_bcj_x86_test_msbyte(buf[i + 4])) 
	{
	  src = get_unaligned_le32(buf + i + 1);
	  while (1) 
	    {
	      dest = src - (s->pos + (uint32_t)i + 5);
	      if (prev_mask == 0)
		break;

	      j = mask_to_bit_num[prev_mask] * 8;
	      b = (uint8_t)(dest >> (24 - j));
	      if (!xz_bcj_x86_test_msbyte(b))
		break;

	      src = dest ^ (((uint32_t)1 << (32 - j)) - 1);
	    }

	  dest &= 0x01FFFFFF;
	  dest |= (uint32_t)0 - (dest & 0x01000000);
	  put_unaligned_le32(dest, buf + i + 1);
	  i += 4;
	} 
      else 
	{
	  prev_mask = (prev_mask << 1) | 1;
	}
    }

  prev_pos = i - prev_pos;
  s->x86_prev_mask = prev_pos > 3 ? 0 : prev_mask << (prev_pos - 1);
  return i;
}

static size_t 
xz_bcj_powerpc(struct xz_dec_bcj *s, uint8_t *buf, size_t size)
{
  size_t i;
  uint32_t instr;

  for (i = 0; i + 4 <= size; i += 4) 
    {
      instr = get_unaligned_be32(buf + i);
      if ((instr & 0xFC000003) == 0x48000001) 
	{
	  instr &= 0x03FFFFFC;
	  instr -= s->pos + (uint32_t)i;
	  instr &= 0x03FFFFFC;
	  instr |= 0x48000001;
	  put_unaligned_be32(instr, buf + i);
	}
    }

  return i;
}

static size_t 
xz_bcj_ia64(struct xz_dec_bcj *s, uint8_t *buf, size_t size)
{
  static const uint8_t branch_table[32] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    4, 4, 6, 6, 0, 0, 7, 7,
    4, 4, 0, 0, 4, 4, 0, 0
  };

  /*
    * The local variables take a little bit stack space, but it's less
    * than what LZMA2 decoder takes, so it doesn't make sense to reduce
    * stack usage here without doing that for the LZMA2 decoder too.
    */

  /* Loop counters */
  size_t i;
  size_t j;

  /* Instruction slot (0, 1, or 2) in the 128-bit instruction word */
  uint32_t slot;

  /* Bitwise offset of the instruction indicated by slot */
  uint32_t bit_pos;

  /* bit_pos split into byte and bit parts */
  uint32_t byte_pos;
  uint32_t bit_res;

  /* Address part of an instruction */
  uint32_t addr;

  /* Mask used to detect which instructions to convert */
  uint32_t mask;

  /* 41-bit instruction stored somewhere in the lowest 48 bits */
  uint64_t instr;

  /* Instruction normalized with bit_res for easier manipulation */
  uint64_t norm;

  for (i = 0; i + 16 <= size; i += 16) 
    {
      mask = branch_table[buf[i] & 0x1F];
      for (slot = 0, bit_pos = 5; slot < 3; ++slot, bit_pos += 41) 
	{
	  if (((mask >> slot) & 1) == 0)
	    continue;

	  byte_pos = bit_pos >> 3;
	  bit_res = bit_pos & 7;
	  instr = 0;
	  for (j = 0; j < 6; ++j)
	    instr |= (uint64_t)(buf[i + j + byte_pos]) << (8 * j);

	  norm = instr >> bit_res;

	  if (((norm >> 37) & 0x0F) == 0x05
		&& ((norm >> 9) & 0x07) == 0) 
	    {
	      addr = (norm >> 13) & 0x0FFFFF;
	      addr |= ((uint32_t)(norm >> 36) & 1) << 20;
	      addr <<= 4;
	      addr -= s->pos + (uint32_t)i;
	      addr >>= 4;

	      norm &= ~((uint64_t)0x8FFFFF << 13);
	      norm |= (uint64_t)(addr & 0x0FFFFF) << 13;
	      norm |= (uint64_t)(addr & 0x100000) << (36 - 20);

	      instr &= (1 << bit_res) - 1;
	      instr |= norm << bit_res;

	      for (j = 0; j < 6; j++)
		buf[i + j + byte_pos] = (uint8_t)(instr >> (8 * j));
	    }
	}
    }

  return i;
}

static size_t 
xz_bcj_arm(struct xz_dec_bcj *s, uint8_t *buf, size_t size)
{
  size_t i;
  uint32_t addr;

  for (i = 0; i + 4 <= size; i += 4) 
    {
      if (buf[i + 3] == 0xEB) 
      {
	addr = (uint32_t)buf[i] | ((uint32_t)buf[i + 1] << 8)
			| ((uint32_t)buf[i + 2] << 16);
	addr <<= 2;
	addr -= s->pos + (uint32_t)i + 8;
	addr >>= 2;
	buf[i] = (uint8_t)addr;
	buf[i + 1] = (uint8_t)(addr >> 8);
	buf[i + 2] = (uint8_t)(addr >> 16);
      }
    }
  return i;
}

static size_t 
xz_bcj_armthumb(struct xz_dec_bcj *s, uint8_t *buf, size_t size)
{
  size_t i;
  uint32_t addr;

  for (i = 0; i + 4 <= size; i += 2) 
    {
      if ((buf[i + 1] & 0xF8) == 0xF0 && (buf[i + 3] & 0xF8) == 0xF8) 
	{
	  addr = (((uint32_t)buf[i + 1] & 0x07) << 19)
			  | ((uint32_t)buf[i] << 11)
			  | (((uint32_t)buf[i + 3] & 0x07) << 8)
			  | (uint32_t)buf[i + 2];
	  addr <<= 1;
	  addr -= s->pos + (uint32_t)i + 4;
	  addr >>= 1;
	  buf[i + 1] = (uint8_t)(0xF0 | ((addr >> 19) & 0x07));
	  buf[i] = (uint8_t)(addr >> 11);
	  buf[i + 3] = (uint8_t)(0xF8 | ((addr >> 8) & 0x07));
	  buf[i + 2] = (uint8_t)addr;
	  i += 2;
      }
    }

  return i;
}

static size_t 
xz_bcj_sparc(struct xz_dec_bcj *s, uint8_t *buf, size_t size)
{
  size_t i;
  uint32_t instr;

  for (i = 0; i + 4 <= size; i += 4) 
    {
      instr = get_unaligned_be32(buf + i);
      if ((instr >> 22) == 0x100 || (instr >> 22) == 0x1FF) 
	{
	  instr <<= 2;
	  instr -= s->pos + (uint32_t)i;
	  instr >>= 2;
	  instr = ((uint32_t)0x40000000 - (instr & 0x400000))
			  | 0x40000000 | (instr & 0x3FFFFF);
	  put_unaligned_be32(instr, buf + i);
	}
    }
  return i;
}


/*
 * Apply the selected BCJ filter. Update *pos and s->pos to match the amount
 * of data that got filtered.
 *
 * NOTE: This is implemented as a switch statement to avoid using function
 * pointers, which could be problematic in the kernel boot code, which must
 * avoid pointers to static data (at least on x86).
 */
static void 
xz_bcj_apply(struct xz_dec_bcj *s,
	     uint8_t *buf, size_t *pos, size_t size)
{
  size_t filtered;

  buf += *pos;
  size -= *pos;
  
  switch (s->type) 
    {
    case BCJ_X86:
	    filtered = xz_bcj_x86(s, buf, size);
	    break;
    case BCJ_POWERPC:
	    filtered = xz_bcj_powerpc(s, buf, size);
	    break;
    case BCJ_IA64:
	    filtered = xz_bcj_ia64(s, buf, size);
	    break;
    case BCJ_ARM:
	    filtered = xz_bcj_arm(s, buf, size);
	    break;
    case BCJ_ARMTHUMB:
	    filtered = xz_bcj_armthumb(s, buf, size);
	    break;
    case BCJ_SPARC:
	    filtered = xz_bcj_sparc(s, buf, size);
	    break;
    default:
      /* Never reached but silence compiler warnings. */
      filtered = 0;
      break;
    }

  *pos += filtered;
  s->pos += filtered;
}

/*
 * Flush pending filtered data from temp to the output buffer.
 * Move the remaining mixture of possibly filtered and unfiltered
 * data to the beginning of temp.
 */
static void 
xz_bcj_flush(struct xz_dec_bcj *s, struct xz_buf *b)
{
  size_t copy_size;

  copy_size = min_t(size_t, s->temp.filtered, b->out_size - b->out_pos);
  memcpy(b->out + b->out_pos, s->temp.buf, copy_size);
  b->out_pos += copy_size;

  s->temp.filtered -= copy_size;
  s->temp.size -= copy_size;
  memmove(s->temp.buf, s->temp.buf + copy_size, s->temp.size);
}

/*
 * The BCJ filter functions are primitive in sense that they process the
 * data in chunks of 1-16 bytes. To hide this issue, this function does
 * some buffering.
 */
static enum xz_ret xz_dec_lzma2_run(struct xz_dec_lzma2 *s, struct xz_buf *b);

static enum xz_ret 
xz_dec_bcj_run(struct xz_dec_bcj *s,
	       struct xz_dec_lzma2 *lzma2,
	       struct xz_buf *b)
{
  size_t out_start;

  /*
    * Flush pending already filtered data to the output buffer. Return
    * immediatelly if we couldn't flush everything, or if the next
    * filter in the chain had already returned XZ_STREAM_END.
    */
  if (s->temp.filtered > 0) 
    {
      xz_bcj_flush(s, b);
      if (s->temp.filtered > 0)
	return XZ_OK;

      if (s->ret == XZ_STREAM_END)
	return XZ_STREAM_END;
    }

  /*
    * If we have more output space than what is currently pending in
    * temp, copy the unfiltered data from temp to the output buffer
    * and try to fill the output buffer by decoding more data from the
    * next filter in the chain. Apply the BCJ filter on the new data
    * in the output buffer. If everything cannot be filtered, copy it
    * to temp and rewind the output buffer position accordingly.
    *
    * This needs to be always run when temp.size == 0 to handle a special
    * case where the output buffer is full and the next filter has no
    * more output coming but hasn't returned XZ_STREAM_END yet.
    */
  if (s->temp.size < b->out_size - b->out_pos || s->temp.size == 0) 
    {
      out_start = b->out_pos;
      memcpy(b->out + b->out_pos, s->temp.buf, s->temp.size);
      b->out_pos += s->temp.size;

      s->ret = xz_dec_lzma2_run(lzma2, b);
      if (s->ret != XZ_STREAM_END && s->ret != XZ_OK)
	return s->ret;

      xz_bcj_apply(s, b->out, &out_start, b->out_pos);

      /*
	* As an exception, if the next filter returned XZ_STREAM_END,
	* we can do that too, since the last few bytes that remain
	* unfiltered are meant to remain unfiltered.
	*/
      if (s->ret == XZ_STREAM_END)
	return XZ_STREAM_END;

      s->temp.size = b->out_pos - out_start;
      b->out_pos -= s->temp.size;
      memcpy(s->temp.buf, b->out + b->out_pos, s->temp.size);

      /*
	* If there wasn't enough input to the next filter to fill
	* the output buffer with unfiltered data, there's no point
	* to try decoding more data to temp.
	*/
      if (b->out_pos + s->temp.size < b->out_size)
	return XZ_OK;
    }

  /*
    * We have unfiltered data in temp. If the output buffer isn't full
    * yet, try to fill the temp buffer by decoding more data from the
    * next filter. Apply the BCJ filter on temp. Then we hopefully can
    * fill the actual output buffer by copying filtered data from temp.
    * A mix of filtered and unfiltered data may be left in temp; it will
    * be taken care on the next call to this function.
    */
  if (b->out_pos < b->out_size) {
    /* Make b->out{,_pos,_size} temporarily point to s->temp. */
    s->out = b->out;
    s->out_pos = b->out_pos;
    s->out_size = b->out_size;
    b->out = s->temp.buf;
    b->out_pos = s->temp.size;
    b->out_size = sizeof(s->temp.buf);

    s->ret = xz_dec_lzma2_run(lzma2, b);

    s->temp.size = b->out_pos;
    b->out = s->out;
    b->out_pos = s->out_pos;
    b->out_size = s->out_size;

    if (s->ret != XZ_OK && s->ret != XZ_STREAM_END)
      return s->ret;

    xz_bcj_apply(s, s->temp.buf, &s->temp.filtered, s->temp.size);

    /*
      * If the next filter returned XZ_STREAM_END, we mark that
      * everything is filtered, since the last unfiltered bytes
      * of the stream are meant to be left as is.
      */
    if (s->ret == XZ_STREAM_END)
      s->temp.filtered = s->temp.size;

    xz_bcj_flush(s, b);
    if (s->temp.filtered > 0)
      return XZ_OK;
  }

  return s->ret;
}

static enum 
xz_ret xz_dec_bcj_reset(struct xz_dec_bcj *s, uint8_t id)
{
  switch (id) 
    {
    case BCJ_X86:
    case BCJ_POWERPC:
    case BCJ_IA64:
    case BCJ_ARM:
    case BCJ_ARMTHUMB:
    case BCJ_SPARC:
      break;

    default:
      /* Unsupported Filter ID */
      return XZ_OPTIONS_ERROR;
    }

  s->type = id;
  s->ret = XZ_OK;
  s->pos = 0;
  s->x86_prev_mask = 0;
  s->temp.filtered = 0;
  s->temp.size = 0;
  return XZ_OK;
}

/**************
 * Dictionary *
 **************/

/*
 * Reset the dictionary state.
 */
static void 
xz_dict_reset(struct xz_dictionary *dict, struct xz_buf *b ATTRIBUTE_UNUSED)
{
  dict->start = 0;
  dict->pos = 0;
  dict->limit = 0;
  dict->full = 0;
}

/* Set dictionary write limit */
static void 
xz_dict_limit(struct xz_dictionary *dict, size_t out_max)
{
  if (dict->size - dict->pos <= out_max)
    dict->limit = dict->size;
  else
    dict->limit = dict->pos + out_max;
}

/* Return true if at least one byte can be written into the dictionary. */
static inline uint8_t 
xz_dict_has_space(const struct xz_dictionary *dict)
{
  return dict->pos < dict->limit;
}

/*
 * Get a byte from the dictionary at the given distance. The distance is
 * assumed to valid, or as a special case, zero when the dictionary is
 * still empty.
 */
static inline uint32_t 
xz_dict_get(const struct xz_dictionary *dict, uint32_t dist)
{
  size_t offset = dict->pos - dist - 1;

  if (dist >= dict->pos)
    offset += dict->size;

  return dict->full > 0 ? dict->buf[offset] : 0;
}

/*
 * Put one byte into the dictionary. It is assumed that there is space for it.
 */
static inline void 
xz_dict_put(struct xz_dictionary *dict, uint8_t byte)
{
  dict->buf[dict->pos++] = byte;

  if (dict->full < dict->pos)
    dict->full = dict->pos;
}

/*
 * Repeat given number of bytes from the given distance. If the distance is
 * invalid, 0 is returned. On success, 1 is returned and *len is
 * updated to indicate how many bytes were left to be repeated.
 */
static int 
xz_dict_repeat(struct xz_dictionary *dict, uint32_t *len, uint32_t dist)
{
  size_t back;
  uint32_t left;

  if (dist >= dict->full || dist >= dict->size)
    return 0;

  left = min_t(size_t, dict->limit - dict->pos, *len);
  *len -= left;

  back = dict->pos - dist - 1;
  if (dist >= dict->pos)
    back += dict->size;

  do {
    dict->buf[dict->pos++] = dict->buf[back++];
    if (back == dict->size)
      back = 0;
  } while (--left > 0);

  if (dict->full < dict->pos)
    dict->full = dict->pos;

  return 1;
}

/* Copy uncompressed data as is from input to dictionary and output buffers. */
static void 
xz_dict_uncompressed(struct xz_dictionary *dict, struct xz_buf *b,
                  uint32_t *left)
{
  size_t copy_size;

  while (*left > 0 
         && b->in_pos < b->in_size
	 && b->out_pos < b->out_size) 
    {
      copy_size = min(b->in_size - b->in_pos,
		      b->out_size - b->out_pos);
      if (copy_size > dict->size - dict->pos)
	      copy_size = dict->size - dict->pos;
      if (copy_size > *left)
	      copy_size = *left;

      *left -= copy_size;

      memmove(dict->buf + dict->pos, b->in + b->in_pos, copy_size);
      dict->pos += copy_size;

      if (dict->full < dict->pos)
	dict->full = dict->pos;

      if (dict->pos == dict->size)
	dict->pos = 0;

    /*
      * use memmove() to avoid undefined behavior with invalid input.
      */
      memmove(b->out + b->out_pos, b->in + b->in_pos,
	      copy_size);

      dict->start = dict->pos;

      b->out_pos += copy_size;
      b->in_pos += copy_size;
    }
}

/*
 * Flush pending data from dictionary to b->out. It is assumed that there is
 * enough space in b->out. This is guaranteed because caller uses xz_dict_limit()
 * before decoding data into the dictionary.
 */
static uint32_t 
xz_dict_flush(struct xz_dictionary *dict, struct xz_buf *b)
{
  size_t copy_size;
  copy_size = dict->pos - dict->start;

  if (dict->pos == dict->size)
    dict->pos = 0;

  /*
    * These buffers cannot overlap
    */
  memcpy(b->out + b->out_pos, dict->buf + dict->start,
	 copy_size);

  dict->start = dict->pos;
  b->out_pos += copy_size;
  return copy_size;
}

/*****************
 * Range decoder *
 *****************/

/* Reset the range decoder. */
static void 
xz_rc_reset(struct xz_rc_dec *rc)
{
  rc->range = (uint32_t)-1;
  rc->code = 0;
  rc->init_bytes_left = LZMA_RC_INIT_BYTES;
}

/*
 * Read the first five initial bytes into rc->code if they haven't been
 * read already. (Yes, the first byte gets completely ignored.)
 */
static int 
xz_rc_read_init(struct xz_rc_dec *rc, struct xz_buf *b)
{
  while (rc->init_bytes_left > 0) 
    {
      if (b->in_pos == b->in_size)
	return 0;

      rc->code = (rc->code << 8) + b->in[b->in_pos++];
      --rc->init_bytes_left;
    }

  return 1;
}

/* Return true if there may not be enough input for the next decoding loop. */
static inline int 
xz_rc_limit_exceeded(const struct xz_rc_dec *rc)
{
  return rc->in_pos > rc->in_limit;
}

/*
 * Return true if it is possible (from point of view of range decoder) that
 * we have reached the end of the LZMA chunk.
 */
static inline int 
xz_rc_is_finished(const struct xz_rc_dec *rc)
{
  return rc->code == 0;
}

/* Read the next input byte if needed. */
static inline void 
xz_rc_normalize(struct xz_rc_dec *rc)
{
  if (rc->range < LZMA_RC_TOP_VALUE) {
    rc->range <<= LZMA_RC_SHIFT_BITS;
    rc->code = (rc->code << LZMA_RC_SHIFT_BITS) + rc->in[rc->in_pos++];
  }
}

/*
 * Decode one bit. In some versions, this function has been splitted in three
 * functions so that the compiler is supposed to be able to more easily avoid
 * an extra branch. In this particular version of the LZMA decoder, this
 * doesn't seem to be a good idea (tested with GCC 3.3.6, 3.4.6, and 4.3.3
 * on x86). Using a non-splitted version results in nicer looking code too.
 *
 * NOTE: This must return an int. Do not make it return a bool or the speed
 * of the code generated by GCC 3.x decreases 10-15 %. (GCC 4.3 doesn't care,
 * and it generates 10-20 % faster code than GCC 3.x from this file anyway.)
 */
static inline int
xz_rc_bit(struct xz_rc_dec *rc, uint16_t *prob)
{
  uint32_t bound;
  int bit;

  xz_rc_normalize(rc);
  bound = (rc->range >> LZMA_RC_BIT_MODEL_TOTAL_BITS) * *prob;
  if (rc->code < bound) 
    {
      rc->range = bound;
      *prob += (LZMA_RC_BIT_MODEL_TOTAL - *prob) >> LZMA_RC_MOVE_BITS;
      bit = 0;
    } 
  else 
    {
      rc->range -= bound;
      rc->code -= bound;
      *prob -= *prob >> LZMA_RC_MOVE_BITS;
      bit = 1;
    }
  return bit;
}

/* Decode a bittree starting from the most significant bit. */
static inline uint32_t 
xz_rc_bittree(struct xz_rc_dec *rc, uint16_t *probs, uint32_t limit)
{
  uint32_t symbol;
  symbol = 1;
  do 
    {
      if (xz_rc_bit(rc, &probs[symbol]))
	symbol = (symbol << 1) + 1;
      else
	symbol <<= 1;
    } 
  while (symbol < limit);

  return symbol;
}

/* Decode a bittree starting from the least significant bit. */
static inline void 
xz_rc_bittree_reverse(struct xz_rc_dec *rc,
		   uint16_t *probs,
		   uint32_t *dest, uint32_t limit)
{
  uint32_t symbol;
  uint32_t i;

  symbol = 1;
  i = 0;

  do 
    {
      if (xz_rc_bit(rc, &probs[symbol])) 
	{
	  symbol = (symbol << 1) + 1;
	  *dest += 1 << i;
	} 
      else 
	{
	  symbol <<= 1;
	}
    } 
  while (++i < limit);
}

/* Decode direct bits (fixed fifty-fifty probability) */
static inline void 
xz_rc_direct(struct xz_rc_dec *rc, uint32_t *dest, uint32_t limit)
{
  uint32_t mask;

  do 
    {
      xz_rc_normalize(rc);
      rc->range >>= 1;
      rc->code -= rc->range;
      mask = (uint32_t)0 - (rc->code >> 31);
      rc->code += rc->range & mask;
      *dest = (*dest << 1) + (mask + 1);
    } 
  while (--limit > 0);
}

/********
 * LZMA *
 ********/

/* Get pointer to literal coder probability array. */
static uint16_t *
xz_lzma_literal_probs(struct xz_dec_lzma2 *s)
{
  uint32_t prev_byte;
  uint32_t low;
  uint32_t high;
  
  prev_byte = xz_dict_get(&s->dict, 0);
  low = prev_byte >> (8 - s->lzma.lc);
  high = (s->dict.pos & s->lzma.literal_pos_mask) << s->lzma.lc;
  
  return s->lzma.literal[low + high];
}

/* Decode a literal (one 8-bit byte) */
static void 
xz_lzma_literal(struct xz_dec_lzma2 *s)
{
  uint16_t *probs;
  uint32_t symbol;
  uint32_t match_byte;
  uint32_t match_bit;
  uint32_t offset;
  uint32_t i;

  probs = xz_lzma_literal_probs(s);

  if (lzma_state_is_literal(s->lzma.state)) 
    {
      symbol = xz_rc_bittree(&s->rc, probs, 0x100);
    } 
  else 
    {
      symbol = 1;
      match_byte = xz_dict_get(&s->dict, s->lzma.rep0) << 1;
      offset = 0x100;

      do 
	{
	  match_bit = match_byte & offset;
	  match_byte <<= 1;
	  i = offset + match_bit + symbol;

	  if (xz_rc_bit(&s->rc, &probs[i])) 
	    {
	      symbol = (symbol << 1) + 1;
	      offset &= match_bit;
	    } 
	  else 
	    {
	      symbol <<= 1;
	      offset &= ~match_bit;
	    }
	} 
      while (symbol < 0x100);
    }

  xz_dict_put(&s->dict, (uint8_t)symbol);
  lzma_state_literal(&s->lzma.state);
}

/* Decode the length of the match into s->lzma.len. */
static void 
xz_lzma_len(struct xz_dec_lzma2 *s, struct xz_lzma_len_dec *l,
	    uint32_t pos_state)
{
  uint16_t *probs;
  uint32_t limit;

  if (!xz_rc_bit(&s->rc, &l->choice)) 
    {
      probs = l->low[pos_state];
      limit = LZMA_LEN_LOW_SYMBOLS;
      s->lzma.len = LZMA_MATCH_LEN_MIN;
    } 
  else 
    {
      if (!xz_rc_bit(&s->rc, &l->choice2)) 
	{
	  probs = l->mid[pos_state];
	  limit = LZMA_LEN_MID_SYMBOLS;
	  s->lzma.len = LZMA_MATCH_LEN_MIN + LZMA_LEN_LOW_SYMBOLS;
	} 
      else 
	{
	  probs = l->high;
	  limit = LZMA_LEN_HIGH_SYMBOLS;
	  s->lzma.len = LZMA_MATCH_LEN_MIN + LZMA_LEN_LOW_SYMBOLS + LZMA_LEN_MID_SYMBOLS;
	}
    }
  s->lzma.len += xz_rc_bittree(&s->rc, probs, limit) - limit;
}

/* Decode a match. The distance will be stored in s->lzma.rep0. */
static void 
xz_lzma_match(struct xz_dec_lzma2 *s, uint32_t pos_state)
{
  uint16_t *probs;
  uint32_t dist_slot;
  uint32_t limit;

  lzma_state_match(&s->lzma.state);

  s->lzma.rep3 = s->lzma.rep2;
  s->lzma.rep2 = s->lzma.rep1;
  s->lzma.rep1 = s->lzma.rep0;

  xz_lzma_len(s, &s->lzma.match_len_dec, pos_state);

  probs = s->lzma.dist_slot[lzma_get_dist_state(s->lzma.len)];
  dist_slot = xz_rc_bittree(&s->rc, probs, LZMA_DIST_SLOTS) - LZMA_DIST_SLOTS;

  if (dist_slot < LZMA_DIST_MODEL_START) 
    {
      s->lzma.rep0 = dist_slot;
    } 
  else 
    {
      limit = (dist_slot >> 1) - 1;
      s->lzma.rep0 = 2 + (dist_slot & 1);

      if (dist_slot < LZMA_DIST_MODEL_END) 
	{
	  s->lzma.rep0 <<= limit;
	  probs = s->lzma.dist_special + s->lzma.rep0 - dist_slot - 1;
	  xz_rc_bittree_reverse(&s->rc, probs, &s->lzma.rep0, limit);
	} 
      else 
	{
	  xz_rc_direct(&s->rc, &s->lzma.rep0, limit - LZMA_ALIGN_BITS);
	  s->lzma.rep0 <<= LZMA_ALIGN_BITS;
	  xz_rc_bittree_reverse(&s->rc, s->lzma.dist_align, &s->lzma.rep0, LZMA_ALIGN_BITS);
	}
    }
}

/*
 * Decode a repeated match. The distance is one of the four most recently
 * seen matches. The distance will be stored in s->lzma.rep0.
 */
static void 
xz_lzma_rep_match(struct xz_dec_lzma2 *s, uint32_t pos_state)
{
  uint32_t tmp;

  if (!xz_rc_bit(&s->rc, &s->lzma.is_rep0[s->lzma.state])) 
    {
      if (!xz_rc_bit(&s->rc, &s->lzma.is_rep0_long[s->lzma.state][pos_state])) 
	{
	  lzma_state_short_rep(&s->lzma.state);
	  s->lzma.len = 1;
	  return;
	}
    } 
  else 
    {
      if (!xz_rc_bit(&s->rc, &s->lzma.is_rep1[s->lzma.state])) 
	{
	      tmp = s->lzma.rep1;
	} 
      else 
	{
	  if (!xz_rc_bit(&s->rc, &s->lzma.is_rep2[s->lzma.state])) 
	    {
	      tmp = s->lzma.rep2;
	    } 
	  else 
	    {
	      tmp = s->lzma.rep3;
	      s->lzma.rep3 = s->lzma.rep2;
	    }

	  s->lzma.rep2 = s->lzma.rep1;
	}

      s->lzma.rep1 = s->lzma.rep0;
      s->lzma.rep0 = tmp;
    }
    
  lzma_state_long_rep(&s->lzma.state);
  xz_lzma_len(s, &s->lzma.rep_len_dec, pos_state);
}

/* LZMA decoder core */
static int 
xz_lzma_main(struct xz_dec_lzma2 *s)
{
  uint32_t pos_state;

  /*
    * If the dictionary was reached during the previous call, try to
    * finish the possibly pending repeat in the dictionary.
    */
  if (xz_dict_has_space(&s->dict) && s->lzma.len > 0)
      xz_dict_repeat(&s->dict, &s->lzma.len, s->lzma.rep0);

  /*
    * Decode more LZMA symbols. One iteration may consume up to
    * LZMA_IN_REQUIRED - 1 bytes.
    */
  while (xz_dict_has_space(&s->dict) && !xz_rc_limit_exceeded(&s->rc)) 
    {
      pos_state = s->dict.pos & s->lzma.pos_mask;

      if (!xz_rc_bit(&s->rc, &s->lzma.is_match[s->lzma.state][pos_state])) 
	{
	  xz_lzma_literal(s);
	} 
      else 
	{
	  if (xz_rc_bit(&s->rc, &s->lzma.is_rep[s->lzma.state]))
	    xz_lzma_rep_match(s, pos_state);
	  else
	    xz_lzma_match(s, pos_state);

	  if (!xz_dict_repeat(&s->dict, &s->lzma.len, s->lzma.rep0))
	    return 0;
	}
    }

  /*
    * Having the range decoder always normalized when we are outside
    * this function makes it easier to correctly handle end of the chunk.
    */
  xz_rc_normalize(&s->rc);
  return 1;
}

/*
 * Reset the LZMA decoder and range decoder state. Dictionary is nore reset
 * here, because LZMA state may be reset without resetting the dictionary.
 */
static void 
xz_lzma_reset(struct xz_dec_lzma2 *s)
{
  uint16_t *probs;
  size_t i;

  s->lzma.state = STATE_LIT_LIT;
  s->lzma.rep0 = 0;
  s->lzma.rep1 = 0;
  s->lzma.rep2 = 0;
  s->lzma.rep3 = 0;

  /*
    * All probabilities are initialized to the same value. This hack
    * makes the code smaller by avoiding a separate loop for each
    * probability array.
    *
    * This could be optimized so that only that part of literal
    * probabilities that are actually required. In the common case
    * we would write 12 KiB less.
    */
  probs = s->lzma.is_match[0];
  for (i = 0; i < LZMA_PROBS_TOTAL; ++i)
    probs[i] = LZMA_RC_BIT_MODEL_TOTAL / 2;

  xz_rc_reset(&s->rc);
}

/*
 * Decode and validate LZMA properties (lc/lp/pb) and calculate the bit masks
 * from the decoded lp and pb values. On success, the LZMA decoder state is
 * reset and 1 is returned.
 */
static int 
xz_lzma_props(struct xz_dec_lzma2 *s, uint8_t props)
{
  if (props > (4 * 5 + 4) * 9 + 8)
    return 0;

  s->lzma.pos_mask = 0;
  while (props >= 9 * 5) 
    {
      props -= 9 * 5;
      ++s->lzma.pos_mask;
    }

  s->lzma.pos_mask = (1 << s->lzma.pos_mask) - 1;

  s->lzma.literal_pos_mask = 0;
  while (props >= 9) 
    {
      props -= 9;
      ++s->lzma.literal_pos_mask;
    }

  s->lzma.lc = props;

  if (s->lzma.lc + s->lzma.literal_pos_mask > 4)
    return 0;

  s->lzma.literal_pos_mask = (1 << s->lzma.literal_pos_mask) - 1;

  xz_lzma_reset(s);

  return 1;
}

/*********
 * LZMA2 *
 *********/

/*
 * The LZMA decoder assumes that if the input limit (s->rc.in_limit) hasn't
 * been exceeded, it is safe to read up to LZMA_IN_REQUIRED bytes. This
 * wrapper function takes care of making the LZMA decoder's assumption safe.
 *
 * As long as there is plenty of input left to be decoded in the current LZMA
 * chunk, we decode directly from the caller-supplied input buffer until
 * there's LZMA_IN_REQUIRED bytes left. Those remaining bytes are copied into
 * s->temp.buf, which (hopefully) gets filled on the next call to this
 * function. We decode a few bytes from the temporary buffer so that we can
 * continue decoding from the caller-supplied input buffer again.
 */
static int 
xz_lzma2_lzma(struct xz_dec_lzma2 *s, struct xz_buf *b)
{
  size_t in_avail;
  uint32_t tmp;

  in_avail = b->in_size - b->in_pos;
  if (s->temp.size > 0 || s->lzma2.compressed == 0) 
    {
      tmp = 2 * LZMA_IN_REQUIRED - s->temp.size;
      if (tmp > s->lzma2.compressed - s->temp.size)
	tmp = s->lzma2.compressed - s->temp.size;
      if (tmp > in_avail)
	tmp = in_avail;

      memcpy(s->temp.buf + s->temp.size, b->in + b->in_pos, tmp);

      if (s->temp.size + tmp == s->lzma2.compressed) 
	{
	  memset(s->temp.buf + s->temp.size + tmp, 0, sizeof(s->temp.buf) - s->temp.size - tmp);
	  s->rc.in_limit = s->temp.size + tmp;
	} 
      else if (s->temp.size + tmp < LZMA_IN_REQUIRED) 
	{
	  s->temp.size += tmp;
	  b->in_pos += tmp;
	  return 1;
	} 
      else 
      {
	s->rc.in_limit = s->temp.size + tmp - LZMA_IN_REQUIRED;
      }

      s->rc.in = s->temp.buf;
      s->rc.in_pos = 0;

      if (!xz_lzma_main(s) || s->rc.in_pos > s->temp.size + tmp)
	return 0;

      s->lzma2.compressed -= s->rc.in_pos;

      if (s->rc.in_pos < s->temp.size) 
	{
	  s->temp.size -= s->rc.in_pos;
	  memmove(s->temp.buf, s->temp.buf + s->rc.in_pos,
			  s->temp.size);
	  return 1;
	}

      b->in_pos += s->rc.in_pos - s->temp.size;
      s->temp.size = 0;
    }

  in_avail = b->in_size - b->in_pos;
  if (in_avail >= LZMA_IN_REQUIRED) 
    {
      s->rc.in = b->in;
      s->rc.in_pos = b->in_pos;

      if (in_avail >= s->lzma2.compressed + LZMA_IN_REQUIRED)
	s->rc.in_limit = b->in_pos + s->lzma2.compressed;
      else
	s->rc.in_limit = b->in_size - LZMA_IN_REQUIRED;

      if (!xz_lzma_main(s))
	return 0;

      in_avail = s->rc.in_pos - b->in_pos;
      if (in_avail > s->lzma2.compressed)
	return 0;

      s->lzma2.compressed -= in_avail;
      b->in_pos = s->rc.in_pos;
    }

  in_avail = b->in_size - b->in_pos;
  if (in_avail < LZMA_IN_REQUIRED) 
    {
      if (in_avail > s->lzma2.compressed)
	in_avail = s->lzma2.compressed;

      memcpy(s->temp.buf, b->in + b->in_pos, in_avail);
      s->temp.size = in_avail;
      b->in_pos += in_avail;
    }
  return 1;
}

/*
 * Take care of the LZMA2 control layer, and forward the job of actual LZMA
 * decoding or copying of uncompressed chunks to other functions.
 */
static enum xz_ret 
xz_dec_lzma2_run(struct xz_dec_lzma2 *s,
		 struct xz_buf *b)
{
  uint32_t tmp;

  while (b->in_pos < b->in_size || s->lzma2.sequence == SEQ_LZMA_RUN) 
    {
      switch (s->lzma2.sequence) 
	{
	case SEQ_CONTROL:
	  /*
	    * LZMA2 control byte
	    *
	    * Exact values:
	    *   0x00   End marker
	    *   0x01   Dictionary reset followed by
	    *          an uncompressed chunk
	    *   0x02   Uncompressed chunk (no dictionary reset)
	    *
	    * Highest three bits (s->control & 0xE0):
	    *   0xE0   Dictionary reset, new properties and state
	    *          reset, followed by LZMA compressed chunk
	    *   0xC0   New properties and state reset, followed
	    *          by LZMA compressed chunk (no dictionary
	    *          reset)
	    *   0xA0   State reset using old properties,
	    *          followed by LZMA compressed chunk (no
	    *          dictionary reset)
	    *   0x80   LZMA chunk (no dictionary or state reset)
	    *
	    * For LZMA compressed chunks, the lowest five bits
	    * (s->control & 1F) are the highest bits of the
	    * uncompressed size (bits 16-20).
	    *
	    * A new LZMA2 stream must begin with a dictionary
	    * reset. The first LZMA chunk must set new
	    * properties and reset the LZMA state.
	    *
	    * Values that don't match anything described above
	    * are invalid and we return XZ_DATA_ERROR.
	    */
	  tmp = b->in[b->in_pos++];

	  if (tmp == 0x00)
	    return XZ_STREAM_END;

	  if (tmp >= 0xE0 || tmp == 0x01) 
	    {
	      s->lzma2.need_props = 1;
	      s->lzma2.need_xz_dict_reset = 0;
	      xz_dict_reset(&s->dict, b);
	    } 
	  else if (s->lzma2.need_xz_dict_reset) 
	    return XZ_DATA_ERROR;


	  if (tmp >= 0x80) 
	    {
	      s->lzma2.uncompressed = (tmp & 0x1F) << 16;
	      s->lzma2.sequence = SEQ_UNCOMPRESSED_1;

	      if (tmp >= 0xC0) 
		{
		  /*
		    * When there are new properties,
		    * state reset is done at
		    * SEQ_PROPERTIES.
		    */
		  s->lzma2.need_props = 0;
		  s->lzma2.next_sequence = SEQ_PROPERTIES;

		} 
	      else if (s->lzma2.need_props) 
		{
		  return XZ_DATA_ERROR;
		}
	      else 
		{
		  s->lzma2.next_sequence = SEQ_LZMA_PREPARE;
		  if (tmp >= 0xA0)
		    xz_lzma_reset(s);
		}
	    } 
	  else 
	    {
	      if (tmp > 0x02)
		return XZ_DATA_ERROR;

	      s->lzma2.sequence = SEQ_COMPRESSED_0;
	      s->lzma2.next_sequence = SEQ_COPY;
	    }

	  break;

	case SEQ_UNCOMPRESSED_1:
	  s->lzma2.uncompressed += (uint32_t)b->in[b->in_pos++] << 8;
	  s->lzma2.sequence = SEQ_UNCOMPRESSED_2;
	  break;

	case SEQ_UNCOMPRESSED_2:
	  s->lzma2.uncompressed += (uint32_t)b->in[b->in_pos++] + 1;
	  s->lzma2.sequence = SEQ_COMPRESSED_0;
	  break;

	case SEQ_COMPRESSED_0:
	  s->lzma2.compressed = (uint32_t)b->in[b->in_pos++] << 8;
	  s->lzma2.sequence = SEQ_COMPRESSED_1;
	  break;

	case SEQ_COMPRESSED_1:
	  s->lzma2.compressed += (uint32_t)b->in[b->in_pos++] + 1;
	  s->lzma2.sequence = s->lzma2.next_sequence;
	  break;

	case SEQ_PROPERTIES:
	  if (!xz_lzma_props(s, b->in[b->in_pos++]))
	    return XZ_DATA_ERROR;

	  s->lzma2.sequence = SEQ_LZMA_PREPARE;

	/* Fall through */

	case SEQ_LZMA_PREPARE:
	  if (s->lzma2.compressed < LZMA_RC_INIT_BYTES)
	    return XZ_DATA_ERROR;

	  if (!xz_rc_read_init(&s->rc, b))
	    return XZ_OK;

	  s->lzma2.compressed -= LZMA_RC_INIT_BYTES;
	  s->lzma2.sequence = SEQ_LZMA_RUN;

	/* Fall through */

	case SEQ_LZMA_RUN:
	  /*
	    * Set dictionary limit to indicate how much we want
	    * to be encoded at maximum. Decode new data into the
	    * dictionary. Flush the new data from dictionary to
	    * b->out. Check if we finished decoding this chunk.
	    * In case the dictionary got full but we didn't fill
	    * the output buffer yet, we may run this loop
	    * multiple times without changing s->lzma2.sequence.
	    */
	  xz_dict_limit(&s->dict, min_t(size_t,
		     b->out_size - b->out_pos,
		     s->lzma2.uncompressed));
	  if (!xz_lzma2_lzma(s, b))
	    return XZ_DATA_ERROR;

	  s->lzma2.uncompressed -= xz_dict_flush(&s->dict, b);

	  if (s->lzma2.uncompressed == 0) 
	    {
	      if (s->lzma2.compressed > 0 
		  || s->lzma.len > 0
		  || !xz_rc_is_finished(&s->rc))
		return XZ_DATA_ERROR;

	      xz_rc_reset(&s->rc);
	      s->lzma2.sequence = SEQ_CONTROL;

	    } 
	  else if (b->out_pos == b->out_size
		   || (b->in_pos == b->in_size
			&& s->temp.size < s->lzma2.compressed)) 
	    {
	      return XZ_OK;
	    }

	  break;

	case SEQ_COPY:
	  xz_dict_uncompressed(&s->dict, b, &s->lzma2.compressed);
	  if (s->lzma2.compressed > 0)
	    return XZ_OK;

	  s->lzma2.sequence = SEQ_CONTROL;
	  break;
	}
    }
  return XZ_OK;
}

static void 
xz_dec_lzma2_create(struct backtrace_state *state,
		    backtrace_error_callback error_callback,
		    void *data, 
		    struct xz_dec_lzma2 *s, uint32_t xz_dict_max)
{
  s->state = state;
  s->data = data;
  s->error_callback = error_callback;
  s->dict.size_max = xz_dict_max;
  s->dict.buf = NULL;
  s->dict.allocated = 0;
}

static enum xz_ret
xz_dec_lzma2_reset(struct xz_dec_lzma2 *s, uint8_t props)
{
  /* This limits dictionary size to 3 GiB to keep parsing simpler. */
  if (props > 39)
    return XZ_OPTIONS_ERROR;

  s->dict.size = 2 + (props & 1);
  s->dict.size <<= (props >> 1) + 11;

  if (s->dict.size > s->dict.size_max)
    return XZ_MEMLIMIT_ERROR;

  s->dict.size = s->dict.size;

  if (s->dict.allocated < s->dict.size) 
    {
      if (s->dict.buf)
	backtrace_free (s->state, s->dict.buf, s->dict.allocated, s->error_callback, s->data);
      
      s->dict.allocated = s->dict.size;
      s->dict.buf = backtrace_alloc(s->state, s->dict.size, s->error_callback, s->data);
      if (s->dict.buf == NULL) 
	{
	  s->dict.allocated = 0;
	  return XZ_MEM_ERROR;
	}
    }

    s->lzma.len = 0;

    s->lzma2.sequence = SEQ_CONTROL;
    s->lzma2.need_xz_dict_reset = 1;

    s->temp.size = 0;

    return XZ_OK;
}

static void 
xz_dec_lzma2_end(struct xz_dec_lzma2 *s)
{
  if (s == NULL)
    return;
  backtrace_free (s->state, s->dict.buf, s->dict.allocated, s->error_callback, s->data);
}

/*
 * Fill s->temp by copying data starting from b->in[b->in_pos]. Caller
 * must have set s->temp.pos to indicate how much data we are supposed
 * to copy into s->temp.buf. Return true once s->temp.pos has reached
 * s->temp.size.
 */
static int 
xz_fill_temp(struct xz_dec *s, struct xz_buf *b)
{
    size_t copy_size = min_t(size_t, b->in_size - b->in_pos, s->temp.size - s->temp.pos);

    memcpy(s->temp.buf + s->temp.pos, b->in + b->in_pos, copy_size);
    b->in_pos += copy_size;
    s->temp.pos += copy_size;

    if (s->temp.pos == s->temp.size) 
      {
	s->temp.pos = 0;
	return 1;
      }

    return 0;
}

/* Decode a variable-length integer (little-endian base-128 encoding) */
static enum xz_ret 
xz_dec_vli(struct xz_dec *s, const uint8_t *in,
	size_t *in_pos, size_t in_size)
{
  uint8_t byte;

  if (s->pos == 0)
    s->vli = 0;

  while (*in_pos < in_size) 
    {
      byte = in[*in_pos];
      ++*in_pos;

      s->vli |= (xz_vli_type)(byte & 0x7F) << s->pos;

      if ((byte & 0x80) == 0) 
	{
	  /* Don't allow non-minimal encodings. */
	  if (byte == 0 && s->pos != 0)
	    return XZ_DATA_ERROR;

	  s->pos = 0;
	  return XZ_STREAM_END;
	}

      s->pos += 7;
      if (s->pos == 7 * VLI_BYTES_MAX)
	return XZ_DATA_ERROR;
    }

  return XZ_OK;
}

/*
 * Decode the Compressed Data field from a Block. Update and validate
 * the observed compressed and uncompressed sizes of the Block so that
 * they don't exceed the values possibly stored in the Block Header
 * (validation assumes that no integer overflow occurs, since xz_vli_type
 * is normally uint64_t). Update the CRC32 or CRC64 value if presence of
 * the CRC32 or CRC64 field was indicated in Stream Header.
 *
 * Once the decoding is finished, validate that the observed sizes match
 * the sizes possibly stored in the Block Header. Update the hash and
 * Block count, which are later used to validate the Index field.
 */
static enum xz_ret 
xz_dec_block(struct xz_dec *s, struct xz_buf *b)
{
  enum xz_ret ret;

  s->in_start = b->in_pos;
  s->out_start = b->out_pos;

  if (s->bcj_active)
    ret = xz_dec_bcj_run(&s->bcj, &s->lzma2, b);
  else
    ret = xz_dec_lzma2_run(&s->lzma2, b);

  s->block.compressed += b->in_pos - s->in_start;
  s->block.uncompressed += b->out_pos - s->out_start;

  /*
    * There is no need to separately check for VLI_UNKNOWN, since
    * the observed sizes are always smaller than VLI_UNKNOWN.
    */
  if (s->block.compressed > s->block_header.compressed
      || s->block.uncompressed > s->block_header.uncompressed)
    return XZ_DATA_ERROR;

  if (s->check_type == XZ_CHECK_CRC32)
    s->crc = elf_crc32(s->crc, b->out + s->out_start,
		       b->out_pos - s->out_start);
  else if (s->check_type == XZ_CHECK_CRC64)
    s->crc = elf_crc64(s->crc, b->out + s->out_start, 
		       b->out_pos - s->out_start);

  if (ret == XZ_STREAM_END) 
    {
      if (s->block_header.compressed != VLI_UNKNOWN
	  && s->block_header.compressed != s->block.compressed)
	return XZ_DATA_ERROR;

      if (s->block_header.uncompressed != VLI_UNKNOWN
	  && s->block_header.uncompressed != s->block.uncompressed)
	return XZ_DATA_ERROR;

      s->block.hash.unpadded += s->block_header.size
		                + s->block.compressed;

      if (s->check_type == XZ_CHECK_CRC32)
	s->block.hash.unpadded += 4;
      else if (s->check_type == XZ_CHECK_CRC64)
	s->block.hash.unpadded += 8;

      s->block.hash.uncompressed += s->block.uncompressed;
      s->block.hash.crc32 = elf_crc32(s->block.hash.crc32,
		      (const uint8_t *)&s->block.hash,
		      sizeof(s->block.hash));

      ++s->block.count;
    }

  return ret;
}

/* Update the Index size and the CRC32 value. */
static void 
xz_index_update(struct xz_dec *s, const struct xz_buf *b)
{
  size_t in_used = b->in_pos - s->in_start;
  s->index.size += in_used;
  s->crc = elf_crc32(s->crc, b->in + s->in_start, in_used);
}

/*
 * Decode the Number of Records, Unpadded Size, and Uncompressed Size
 * fields from the Index field. That is, Index Padding and CRC32 are not
 * decoded by this function.
 *
 * This can return XZ_OK (more input needed), XZ_STREAM_END (everything
 * successfully decoded), or XZ_DATA_ERROR (input is corrupt).
 */
static enum xz_ret 
xz_dec_index(struct xz_dec *s, struct xz_buf *b)
{
  enum xz_ret ret;

  do 
    {
      ret = xz_dec_vli(s, b->in, &b->in_pos, b->in_size);
      if (ret != XZ_STREAM_END) 
	{
	  xz_index_update(s, b);
	  return ret;
	}

      switch (s->index.sequence) 
	{
	case SEQ_INDEX_COUNT:
	  s->index.count = s->vli;

	  /*
	    * Validate that the Number of Records field
	    * indicates the same number of Records as
	    * there were Blocks in the Stream.
	    */
	  if (s->index.count != s->block.count)
	    return XZ_DATA_ERROR;

	  s->index.sequence = SEQ_INDEX_UNPADDED;
	  break;

	case SEQ_INDEX_UNPADDED:
	  s->index.hash.unpadded += s->vli;
	  s->index.sequence = SEQ_INDEX_UNCOMPRESSED;
	  break;

	case SEQ_INDEX_UNCOMPRESSED:
	  s->index.hash.uncompressed += s->vli;
	  s->index.hash.crc32 = elf_crc32(s->index.hash.crc32,
			  (const uint8_t *)&s->index.hash,
			  sizeof(s->index.hash));
	  --s->index.count;
	  s->index.sequence = SEQ_INDEX_UNPADDED;
	  break;
	}
    } 
  while (s->index.count > 0);

  return XZ_STREAM_END;
}

/*
 * Validate that the next four or eight input bytes match the value
 * of s->crc. s->pos must be zero when starting to validate the first byte.
 * The "bits" argument allows using the same code for both CRC32 and CRC64.
 */
static enum xz_ret 
xz_cxz_rc_validate(struct xz_dec *s, struct xz_buf *b,
	        uint32_t bits)
{
  do 
    {
      if (b->in_pos == b->in_size)
	return XZ_OK;

      if (((s->crc >> s->pos) & 0xFF) != b->in[b->in_pos++])
	return XZ_DATA_ERROR;

      s->pos += 8;
    } 
  while (s->pos < bits);

  s->crc = 0;
  s->pos = 0;

  return XZ_STREAM_END;
}

/* Decode the Stream Header field (the first 12 bytes of the .xz Stream). */
static enum xz_ret 
xz_dec_stream_header(struct xz_dec *s)
{
  if (memcmp(s->temp.buf, XZ_HEADER_MAGIC, XZ_HEADER_MAGIC_SIZE) != 0)
    return XZ_FORMAT_ERROR;

  if (elf_crc32(0, s->temp.buf + XZ_HEADER_MAGIC_SIZE, 2)
	!= get_le32(s->temp.buf + XZ_HEADER_MAGIC_SIZE + 2))
    return XZ_DATA_ERROR;

  if (s->temp.buf[XZ_HEADER_MAGIC_SIZE] != 0)
    return XZ_OPTIONS_ERROR;

  /*
    * Of integrity checks, we support none (Check ID = 0),
    * CRC32 (Check ID = 1), and optionally CRC64 (Check ID = 4).
    */
  s->check_type = s->temp.buf[XZ_HEADER_MAGIC_SIZE + 1];

  if (s->check_type != XZ_CHECK_CRC32 && s->check_type != XZ_CHECK_CRC64)
    return XZ_OPTIONS_ERROR;

  return XZ_OK;
}

/* Decode the Stream Footer field (the last 12 bytes of the .xz Stream) */
static enum xz_ret 
xz_dec_stream_footer(struct xz_dec *s)
{
  if (memcmp(s->temp.buf + 10, XZ_FOOTER_MAGIC, XZ_FOOTER_MAGIC_SIZE) != 0)
    return XZ_DATA_ERROR;

  if (elf_crc32(0, s->temp.buf + 4, 6) != get_le32(s->temp.buf))
    return XZ_DATA_ERROR;

  /*
    * Validate Backward Size. Note that we never added the size of the
    * Index CRC32 field to s->index.size, thus we use s->index.size / 4
    * instead of s->index.size / 4 - 1.
    */
  if ((s->index.size >> 2) != get_le32(s->temp.buf + 4))
    return XZ_DATA_ERROR;

  if (s->temp.buf[8] != 0 || s->temp.buf[9] != s->check_type)
    return XZ_DATA_ERROR;

  /*
    * Use XZ_STREAM_END instead of XZ_OK to be more convenient
    * for the caller.
    */
  return XZ_STREAM_END;
}

/* Decode the Block Header and initialize the filter chain. */
static enum xz_ret 
xz_dec_block_header(struct xz_dec *s)
{
  enum xz_ret ret;

  /*
    * Validate the CRC32. We know that the temp buffer is at least
    * eight bytes so this is safe.
    */
  s->temp.size -= 4;
  if (elf_crc32(0, s->temp.buf, s->temp.size) != get_le32(s->temp.buf + s->temp.size))
    return XZ_DATA_ERROR;

  s->temp.pos = 2;

  /*
    * Catch unsupported Block Flags. We support only one or two filters
    * in the chain, so we catch that with the same test.
    */
  if (s->temp.buf[1] & 0x3E)
    return XZ_OPTIONS_ERROR;

  /* Compressed Size */
  if (s->temp.buf[1] & 0x40) 
    {
      if (xz_dec_vli(s, s->temp.buf, &s->temp.pos, s->temp.size)
	  != XZ_STREAM_END)
	return XZ_DATA_ERROR;

      s->block_header.compressed = s->vli;
    } 
  else 
    {
      s->block_header.compressed = VLI_UNKNOWN;
    }

  /* Uncompressed Size */
  if (s->temp.buf[1] & 0x80) 
    {
      if (xz_dec_vli(s, s->temp.buf, &s->temp.pos, s->temp.size)
	  != XZ_STREAM_END)
	return XZ_DATA_ERROR;

      s->block_header.uncompressed = s->vli;
    } 
  else 
    {
      s->block_header.uncompressed = VLI_UNKNOWN;
    }

  /* If there are two filters, the first one must be a BCJ filter. */
  s->bcj_active = s->temp.buf[1] & 0x01;
  if (s->bcj_active) 
    {
      if (s->temp.size - s->temp.pos < 2)
	return XZ_OPTIONS_ERROR;

      ret = xz_dec_bcj_reset(&s->bcj, s->temp.buf[s->temp.pos++]);
      if (ret != XZ_OK)
	return ret;

      /*
	* We don't support custom start offset,
	* so Size of Properties must be zero.
	*/
      if (s->temp.buf[s->temp.pos++] != 0x00)
	return XZ_OPTIONS_ERROR;
    }

  /* Valid Filter Flags always take at least two bytes. */
  if (s->temp.size - s->temp.pos < 2)
    return XZ_DATA_ERROR;

  /* Filter ID = LZMA2 */
  if (s->temp.buf[s->temp.pos++] != 0x21)
    return XZ_OPTIONS_ERROR;

  /* Size of Properties = 1-byte Filter Properties */
  if (s->temp.buf[s->temp.pos++] != 0x01)
    return XZ_OPTIONS_ERROR;

  /* Filter Properties contains LZMA2 dictionary size. */
  if (s->temp.size - s->temp.pos < 1)
    return XZ_DATA_ERROR;

  ret = xz_dec_lzma2_reset(&s->lzma2, s->temp.buf[s->temp.pos++]);
  if (ret != XZ_OK)
    return ret;

  /* The rest must be Header Padding. */
  while (s->temp.pos < s->temp.size)
    if (s->temp.buf[s->temp.pos++] != 0x00)
      return XZ_OPTIONS_ERROR;

  s->temp.pos = 0;
  s->block.compressed = 0;
  s->block.uncompressed = 0;

  return XZ_OK;
}

static enum xz_ret 
xz_dec_main(struct xz_dec *s, struct xz_buf *b)
{
  enum xz_ret ret;

  /*
    * Store the start position for the case when we are in the middle
    * of the Index field.
    */
  s->in_start = b->in_pos;

  while (1) 
    {
      switch (s->sequence) 
	{
	case SEQ_STREAM_HEADER:
	  /*
	    * Stream Header is copied to s->temp, and then
	    * decoded from there. This way if the caller
	    * gives us only little input at a time, we can
	    * still keep the Stream Header decoding code
	    * simple. Similar approach is used in many places
	    * in this file.
	    */
	  if (!xz_fill_temp(s, b))
	    return XZ_OK;

	  /*
	    * If xz_dec_stream_header() returns
	    * XZ_UNSUPPORTED_CHECK, it is still possible
	    * to continue decoding. Thus, update s->sequence before calling
	    * xz_dec_stream_header().
	    */
	  s->sequence = SEQ_BLOCK_START;

	  ret = xz_dec_stream_header(s);
	  if (ret != XZ_OK)
	    return ret;

	  /* Fall through */

	case SEQ_BLOCK_START:
	  /* We need one byte of input to continue. */
	  if (b->in_pos == b->in_size)
	    return XZ_OK;

	  /* See if this is the beginning of the Index field. */
	  if (b->in[b->in_pos] == 0) 
	    {
	      s->in_start = b->in_pos++;
	      s->sequence = SEQ_INDEX;
	      break;
	    }

	  /*
	    * Calculate the size of the Block Header and
	    * prepare to decode it.
	    */
	  s->block_header.size = ((uint32_t)b->in[b->in_pos] + 1) * 4;
	  s->temp.size = s->block_header.size;
	  s->temp.pos = 0;
	  s->sequence = SEQ_BLOCK_HEADER;

	  /* Fall through */

	case SEQ_BLOCK_HEADER:
	  if (!xz_fill_temp(s, b))
	    return XZ_OK;

	  ret = xz_dec_block_header(s);
	  if (ret != XZ_OK)
	    return ret;

	  s->sequence = SEQ_BLOCK_UNCOMPRESS;

	  /* Fall through */

	case SEQ_BLOCK_UNCOMPRESS:
	      ret = xz_dec_block(s, b);
	      if (ret != XZ_STREAM_END)
		return ret;

	      s->sequence = SEQ_BLOCK_PADDING;

	  /* Fall through */

	case SEQ_BLOCK_PADDING:
	  /*
	    * Size of Compressed Data + Block Padding
	    * must be a multiple of four. We don't need
	    * s->block.compressed for anything else
	    * anymore, so we use it here to test the size
	    * of the Block Padding field.
	    */
	  while (s->block.compressed & 3) 
	    {
	      if (b->in_pos == b->in_size)
		return XZ_OK;

	      if (b->in[b->in_pos++] != 0)
		return XZ_DATA_ERROR;

	      ++s->block.compressed;
	    }

	  s->sequence = SEQ_BLOCK_CHECK;

	/* Fall through */

	case SEQ_BLOCK_CHECK:
	  if (s->check_type == XZ_CHECK_CRC32) 
	    {
	      ret = xz_cxz_rc_validate(s, b, 32);
	      if (ret != XZ_STREAM_END)
		return ret;
	    }
	  else if (s->check_type == XZ_CHECK_CRC64) 
	    {
	      ret = xz_cxz_rc_validate(s, b, 64);
	      if (ret != XZ_STREAM_END)
		return ret;
	    }

	  s->sequence = SEQ_BLOCK_START;
	  break;

	case SEQ_INDEX:
	  ret = xz_dec_index(s, b);
	  if (ret != XZ_STREAM_END)
	      return ret;

	  s->sequence = SEQ_INDEX_PADDING;

	/* Fall through */

	case SEQ_INDEX_PADDING:
	  while ((s->index.size + (b->in_pos - s->in_start)) & 3) 
	    {
	      if (b->in_pos == b->in_size) 
		{
		  xz_index_update(s, b);
		  return XZ_OK;
		}

		if (b->in[b->in_pos++] != 0)
		  return XZ_DATA_ERROR;
	    }

	  /* Finish the CRC32 value and Index size. */
	  xz_index_update(s, b);

	  /* Compare the hashes to validate the Index field. */
	  if (memcmp(&s->block.hash, &s->index.hash, sizeof(s->block.hash)) != 0)
	    return XZ_DATA_ERROR;

	  s->sequence = SEQ_INDEX_CRC32;

	/* Fall through */

	case SEQ_INDEX_CRC32:
	  ret = xz_cxz_rc_validate(s, b, 32);
	  if (ret != XZ_STREAM_END)
	    return ret;

	  s->temp.size = XZ_STREAM_HEADER_SIZE;
	  s->sequence = SEQ_STREAM_FOOTER;

	/* Fall through */
	case SEQ_STREAM_FOOTER:
	  if (!xz_fill_temp(s, b))
	    return XZ_OK;
	  return xz_dec_stream_footer(s);
	}
    }

  /* Never reached */
}

/*
 * xz_dec_run() is a wrapper for xz_dec_main() to handle some special cases
 *
 * We must return XZ_BUF_ERROR when it seems clear that we
 * are not going to make any progress anymore. This is to prevent the caller
 * from calling us infinitely when the input file is truncated or otherwise
 * corrupt. Since zlib-style API allows that the caller fills the input buffer
 * only when the decoder doesn't produce any new output, we have to be careful
 * to avoid returning XZ_BUF_ERROR too easily: XZ_BUF_ERROR is returned only
 * after the second consecutive call to xz_dec_run() that makes no progress.
 */
static enum xz_ret 
xz_dec_run(struct xz_dec *s, struct xz_buf *b)
{
  size_t in_start;
  size_t out_start;
  enum xz_ret ret;

  in_start = b->in_pos;
  out_start = b->out_pos;
  ret = xz_dec_main(s, b);

  if (ret == XZ_OK && in_start == b->in_pos
      && out_start == b->out_pos) 
    {
      if (s->allow_buf_error)
	ret = XZ_BUF_ERROR;

      s->allow_buf_error = 1;
    } 
  else 
    {
      s->allow_buf_error = 0;
    }

  return ret;
}

static void 
xz_dec_reset(struct xz_dec *s)
{
  s->sequence = SEQ_STREAM_HEADER;
  s->allow_buf_error = 0;
  s->pos = 0;
  s->crc = 0;
  memset(&s->block, 0, sizeof(s->block));
  memset(&s->index, 0, sizeof(s->index));
  s->temp.pos = 0;
  s->temp.size = XZ_STREAM_HEADER_SIZE;
}

static void 
xz_dec_init(struct backtrace_state *state,
	    backtrace_error_callback error_callback,
	    void *data, 
	    struct xz_dec *s, uint32_t xz_dict_max)
{
  xz_dec_lzma2_create(state, error_callback, data, &s->lzma2, xz_dict_max);
  xz_dec_reset(s);
}

static void 
xz_dec_end(struct xz_dec *s)
{
  if (s == NULL)
    return;
  
  xz_dec_lzma2_end(&s->lzma2);
}

#define ELF_LZMA_UNCOMPRESSOR_GROW_FACTOR 2
static int
elf_uncompress_lzma_gnu_debugdata(struct backtrace_state *state,
				  backtrace_error_callback error_callback, void *data,
                                  const char *compressed, size_t compressed_size,
                                  struct backtrace_vector *uncompressed)
{
  struct xz_dec dec;
  struct xz_buf buf;
  size_t total_size;
  enum xz_ret ret;
  
  memset (uncompressed, 0, sizeof (struct backtrace_vector));
  if (backtrace_vector_grow(state, compressed_size * ELF_LZMA_UNCOMPRESSOR_GROW_FACTOR, error_callback, data, uncompressed) == NULL) {
    error_callback(data, "elf_uncompress_lzma_gnu_debugdata ran out of memory", ENOMEM);
    return 0;
  }
  
  xz_dec_init(state, error_callback, data, &dec, (uint32_t)-1);    
  buf.out_size = uncompressed->size;
  buf.out = uncompressed->base;
  buf.out_pos = 0;
  
  buf.in = (const unsigned char *)compressed;
  buf.in_pos = 0;
  buf.in_size = compressed_size;
  total_size = 0;
  do 
    {
      ret = xz_dec_run(&dec, &buf);
      total_size += buf.out_pos;
      if (buf.out_pos == buf.out_size && ret == XZ_OK) 
	{
	  buf.out = backtrace_vector_grow(state, compressed_size * ELF_LZMA_UNCOMPRESSOR_GROW_FACTOR, error_callback, data, uncompressed);
	  if (buf.out == NULL) {
	    ret = XZ_MEM_ERROR;
	    break;
	  }
	  
	  buf.out_size = compressed_size * ELF_LZMA_UNCOMPRESSOR_GROW_FACTOR;
	  buf.out_pos = 0;
	}
    } 
  while (ret == XZ_OK);
  
  xz_dec_end(&dec);
  switch (ret) 
    {
    case XZ_STREAM_END:
      return 1;
    case XZ_MEM_ERROR:
      error_callback(data, "XZ decompressor ran out of memory", ENOMEM);
      break;
    case XZ_FORMAT_ERROR:
      error_callback(data, "Input is not in the XZ format (wrong magic bytes)", EINVAL);
      break;
    case XZ_OPTIONS_ERROR:
      error_callback(data, "Input was encoded with settings that are not "
		            "supported by this XZ decoder", EINVAL);
      break;
    case XZ_DATA_ERROR:
    case XZ_BUF_ERROR:
      error_callback(data, "XZ-compressed data is corrupt", EINVAL);
      break;
    default:
      error_callback(data, "Bug in the XZ decompressor", EIO);
      break;
    }
    
  backtrace_vector_free (state, uncompressed, error_callback, data);
  return 0;
}
#endif

static int
elf_get_view(struct backtrace_state *state,
             int fd,
             const char *memory, uint64_t memory_size,
             off_t offset, uint64_t size,
             backtrace_error_callback error_callback,
             void *data, struct backtrace_view *view) {
  union {
    const void *cv;
    void *v;
  } const_cast;

  if (memory == NULL)
    return backtrace_get_view(state, fd, offset, size, error_callback, data, view);

  if (offset + size > memory_size)
    {
      error_callback(data, "can't create memory view", EINVAL);
      return 0;
    }

  view->data = backtrace_alloc(state, size, error_callback, data);
  if (view->data == NULL)
    {
      error_callback(data, "can't allocate memory", errno);
      return 0;
    }

  const_cast.cv = view->data;
  memcpy(const_cast.v, memory + offset, size);
  view->base = const_cast.v;
  view->len = size;
  return 1;
}
static void
elf_release_view(struct backtrace_state *state,
		 struct backtrace_view *view,
		 backtrace_error_callback error_callback,
		 void *data,
		 int use_backtrace_free)
{
  if (!use_backtrace_free)
    backtrace_release_view(state, view, error_callback, data);
  else
    backtrace_free(state, view->base, view->len, error_callback, data);
}

/* Add the backtrace data for one ELF file.  Returns 1 on success,
   0 on failure (in both cases descriptor is closed) or -1 if exe
   is non-zero and the ELF file is ET_DYN, which tells the caller that
   elf_add will need to be called on the descriptor again after
   base_address is determined.  */

static int
elf_add (struct backtrace_state *state, const char *filename, int descriptor,
	 uintptr_t base_address, backtrace_error_callback error_callback,
	 void *data, fileline *fileline_fn, int *found_sym, int *found_dwarf,
	 struct dwarf_data **fileline_entry, int exe, int debuginfo,
	 const char *with_buildid_data, uint32_t with_buildid_size,
	 const char *minidebuginfo_data, uint32_t minidebuginfo_size)
{
  struct backtrace_view ehdr_view;
  b_elf_ehdr ehdr;
  off_t shoff;
  unsigned int shnum;
  unsigned int shstrndx;
  struct backtrace_view shdrs_view;
  int shdrs_view_valid;
  const b_elf_shdr *shdrs;
  const b_elf_shdr *shstrhdr;
  size_t shstr_size;
  off_t shstr_off;
  struct backtrace_view names_view;
  int names_view_valid;
  const char *names;
  unsigned int symtab_shndx;
  unsigned int dynsym_shndx;
  unsigned int i;
  struct debug_section_info sections[DEBUG_MAX];
  struct debug_section_info zsections[DEBUG_MAX];
  struct backtrace_view symtab_view;
  int symtab_view_valid;
  struct backtrace_view strtab_view;
  int strtab_view_valid;
  struct backtrace_view buildid_view;
  int buildid_view_valid;
  const char *buildid_data;
  uint32_t buildid_size;
  struct backtrace_view debuglink_view;
  int debuglink_view_valid;
  const char *debuglink_name;
  uint32_t debuglink_crc;
  struct backtrace_view debugaltlink_view;
  int debugaltlink_view_valid;
  const char *debugaltlink_name;
  const char *debugaltlink_buildid_data;
  uint32_t debugaltlink_buildid_size;
  off_t min_offset;
  off_t max_offset;
  off_t debug_size;
  struct backtrace_view debug_view;
  int debug_view_valid;
  unsigned int using_debug_view;
  uint16_t *zdebug_table;
  struct backtrace_view split_debug_view[DEBUG_MAX];
  unsigned char split_debug_view_valid[DEBUG_MAX];
  struct elf_ppc64_opd_data opd_data, *opd;
  struct dwarf_sections dwarf_sections;
  struct backtrace_view gnu_debugdata;
  int gnu_debugdata_valid;
  size_t gnu_debugdata_size;
  const char *gnu_debugdata_data;
  int use_backtrace_free_for_views;

  if (!debuginfo)
    {
      *found_sym = 0;
      *found_dwarf = 0;
    }

  shdrs_view_valid = 0;
  names_view_valid = 0;
  symtab_view_valid = 0;
  strtab_view_valid = 0;
  buildid_view_valid = 0;
  buildid_data = NULL;
  buildid_size = 0;
  debuglink_view_valid = 0;
  debuglink_name = NULL;
  debuglink_crc = 0;
  debugaltlink_view_valid = 0;
  debugaltlink_name = NULL;
  debugaltlink_buildid_data = NULL;
  debugaltlink_buildid_size = 0;
  debug_view_valid = 0;
  memset (&split_debug_view_valid[0], 0, sizeof split_debug_view_valid);
  opd = NULL;
  gnu_debugdata_valid = 0;
  gnu_debugdata_size = 0;
  gnu_debugdata_data = NULL;
  use_backtrace_free_for_views = (minidebuginfo_data != NULL);

  if (!elf_get_view (state, descriptor,
		     minidebuginfo_data, minidebuginfo_size,
		     0, sizeof ehdr, error_callback,
		     data, &ehdr_view))
    goto fail;

  memcpy (&ehdr, ehdr_view.data, sizeof ehdr);

  elf_release_view (state, &ehdr_view, error_callback,
		    data, use_backtrace_free_for_views);

  if (ehdr.e_ident[EI_MAG0] != ELFMAG0
      || ehdr.e_ident[EI_MAG1] != ELFMAG1
      || ehdr.e_ident[EI_MAG2] != ELFMAG2
      || ehdr.e_ident[EI_MAG3] != ELFMAG3)
    {
      error_callback (data, "executable file is not ELF", 0);
      goto fail;
    }
  if (ehdr.e_ident[EI_VERSION] != EV_CURRENT)
    {
      error_callback (data, "executable file is unrecognized ELF version", 0);
      goto fail;
    }

#if BACKTRACE_ELF_SIZE == 32
#define BACKTRACE_ELFCLASS ELFCLASS32
#else
#define BACKTRACE_ELFCLASS ELFCLASS64
#endif

  if (ehdr.e_ident[EI_CLASS] != BACKTRACE_ELFCLASS)
    {
      error_callback (data, "executable file is unexpected ELF class", 0);
      goto fail;
    }

  if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB
      && ehdr.e_ident[EI_DATA] != ELFDATA2MSB)
    {
      error_callback (data, "executable file has unknown endianness", 0);
      goto fail;
    }

  /* If the executable is ET_DYN, it is either a PIE, or we are running
     directly a shared library with .interp.  We need to wait for
     dl_iterate_phdr in that case to determine the actual base_address.  */
  if (exe && ehdr.e_type == ET_DYN)
    return -1;

  shoff = ehdr.e_shoff;
  shnum = ehdr.e_shnum;
  shstrndx = ehdr.e_shstrndx;

  if ((shnum == 0 || shstrndx == SHN_XINDEX)
      && shoff != 0)
    {
      struct backtrace_view shdr_view;
      const b_elf_shdr *shdr;

      if (!elf_get_view (state, descriptor,
			 minidebuginfo_data, minidebuginfo_size,
			 shoff, sizeof shdr, error_callback,
			 data, &shdr_view))
	goto fail;

      shdr = (const b_elf_shdr *) shdr_view.data;

      if (shnum == 0)
	shnum = shdr->sh_size;

      if (shstrndx == SHN_XINDEX)
	{
	  shstrndx = shdr->sh_link;

	  /* Versions of the GNU binutils between 2.12 and 2.18 did
	     not handle objects with more than SHN_LORESERVE sections
	     correctly.  All large section indexes were offset by
	     0x100.  There is more information at
	     http://sourceware.org/bugzilla/show_bug.cgi?id-5900 .
	     Fortunately these object files are easy to detect, as the
	     GNU binutils always put the section header string table
	     near the end of the list of sections.  Thus if the
	     section header string table index is larger than the
	     number of sections, then we know we have to subtract
	     0x100 to get the real section index.  */
	  if (shstrndx >= shnum && shstrndx >= SHN_LORESERVE + 0x100)
	    shstrndx -= 0x100;
	}

      elf_release_view (state, &shdr_view, error_callback,
			data, use_backtrace_free_for_views);
    }

  /* To translate PC to file/line when using DWARF, we need to find
     the .debug_info and .debug_line sections.  */

  /* Read the section headers, skipping the first one.  */

  if (!elf_get_view (state, descriptor,
		     minidebuginfo_data, minidebuginfo_size,
		     shoff + sizeof (b_elf_shdr),
		     (shnum - 1) * sizeof (b_elf_shdr),
		     error_callback, data, &shdrs_view))
    goto fail;
  shdrs_view_valid = 1;
  shdrs = (const b_elf_shdr *) shdrs_view.data;

  /* Read the section names.  */

  shstrhdr = &shdrs[shstrndx - 1];
  shstr_size = shstrhdr->sh_size;
  shstr_off = shstrhdr->sh_offset;

  if (!elf_get_view (state, descriptor,
		     minidebuginfo_data, minidebuginfo_size,
		     shstr_off, shstrhdr->sh_size,
		     error_callback, data, &names_view))
    goto fail;
  names_view_valid = 1;
  names = (const char *) names_view.data;

  symtab_shndx = 0;
  dynsym_shndx = 0;

  memset (sections, 0, sizeof sections);
  memset (zsections, 0, sizeof zsections);

  /* Look for the symbol table.  */
  for (i = 1; i < shnum; ++i)
    {
      const b_elf_shdr *shdr;
      unsigned int sh_name;
      const char *name;
      int j;

      shdr = &shdrs[i - 1];

      if (shdr->sh_type == SHT_SYMTAB)
	symtab_shndx = i;
      else if (shdr->sh_type == SHT_DYNSYM)
	dynsym_shndx = i;

      sh_name = shdr->sh_name;
      if (sh_name >= shstr_size)
	{
	  error_callback (data, "ELF section name out of range", 0);
	  goto fail;
	}

      name = names + sh_name;

      for (j = 0; j < (int) DEBUG_MAX; ++j)
	{
	  if (strcmp (name, dwarf_section_names[j]) == 0)
	    {
	      sections[j].offset = shdr->sh_offset;
	      sections[j].size = shdr->sh_size;
	      sections[j].compressed = (shdr->sh_flags & SHF_COMPRESSED) != 0;
	      break;
	    }
	}

      if (name[0] == '.' && name[1] == 'z')
	{
	  for (j = 0; j < (int) DEBUG_MAX; ++j)
	    {
	      if (strcmp (name + 2, dwarf_section_names[j] + 1) == 0)
		{
		  zsections[j].offset = shdr->sh_offset;
		  zsections[j].size = shdr->sh_size;
		  break;
		}
	    }
	}

      /* Read the build ID if present.  This could check for any
	 SHT_NOTE section with the right note name and type, but gdb
	 looks for a specific section name.  */
      if ((!debuginfo || with_buildid_data != NULL)
	  && !buildid_view_valid
	  && strcmp (name, ".note.gnu.build-id") == 0)
	{
	  const b_elf_note *note;

	  if (!elf_get_view (state, descriptor,
			     minidebuginfo_data, minidebuginfo_size,
			     shdr->sh_offset, shdr->sh_size,
			     error_callback, data, &buildid_view))
	    goto fail;

	  buildid_view_valid = 1;
	  note = (const b_elf_note *) buildid_view.data;
	  if (note->type == NT_GNU_BUILD_ID
	      && note->namesz == 4
	      && strncmp (note->name, "GNU", 4) == 0
	      && shdr->sh_size <= 12 + ((note->namesz + 3) & ~ 3) + note->descsz)
	    {
	      buildid_data = &note->name[0] + ((note->namesz + 3) & ~ 3);
	      buildid_size = note->descsz;
	    }

	  if (with_buildid_size != 0)
	    {
	      if (buildid_size != with_buildid_size)
		goto fail;

	      if (memcmp (buildid_data, with_buildid_data, buildid_size) != 0)
		goto fail;
	    }
	}

      /* Read the debuglink file if present.  */
      if (!debuginfo
	  && !debuglink_view_valid
	  && strcmp (name, ".gnu_debuglink") == 0)
	{
	  const char *debuglink_data;
	  size_t cxz_rc_offset;

	  if (!elf_get_view (state, descriptor,
			     minidebuginfo_data, minidebuginfo_size,
			     shdr->sh_offset, shdr->sh_size,
			     error_callback, data, &debuglink_view))
	    goto fail;

	  debuglink_view_valid = 1;
	  debuglink_data = (const char *) debuglink_view.data;
	  cxz_rc_offset = strnlen (debuglink_data, shdr->sh_size);
	  cxz_rc_offset = (cxz_rc_offset + 3) & ~3;
	  if (cxz_rc_offset + 4 <= shdr->sh_size)
	    {
	      debuglink_name = debuglink_data;
	      debuglink_crc = *(const uint32_t*)(debuglink_data + cxz_rc_offset);
	    }
	}

      if (!debugaltlink_view_valid
	  && strcmp (name, ".gnu_debugaltlink") == 0)
	{
	  const char *debugaltlink_data;
	  size_t debugaltlink_name_len;

	  if (!elf_get_view (state, descriptor,
			     minidebuginfo_data, minidebuginfo_size,
			     shdr->sh_offset, shdr->sh_size, error_callback,
			     data, &debugaltlink_view))
	    goto fail;

	  debugaltlink_view_valid = 1;
	  debugaltlink_data = (const char *) debugaltlink_view.data;
	  debugaltlink_name = debugaltlink_data;
	  debugaltlink_name_len = strnlen (debugaltlink_data, shdr->sh_size);
	  if (debugaltlink_name_len < shdr->sh_size)
	    {
	      /* Include terminating zero.  */
	      debugaltlink_name_len += 1;

	      debugaltlink_buildid_data
		= debugaltlink_data + debugaltlink_name_len;
	      debugaltlink_buildid_size = shdr->sh_size - debugaltlink_name_len;
	    }
	}

#     ifdef MINI_DEBUG_INFO
      if (!debuginfo
	  && !debuglink_view_valid
	  && !debugaltlink_view_valid
	  && strcmp(name, ".gnu_debugdata") == 0)
	{
	  if (!elf_get_view(state, descriptor, minidebuginfo_data,
			    minidebuginfo_size, shdr->sh_offset,
			    shdr->sh_size, error_callback, data,
			    &gnu_debugdata))
	    goto fail;

	  gnu_debugdata_valid = 1;
	  gnu_debugdata_size = shdr->sh_size;
	  gnu_debugdata_data = gnu_debugdata.data;
	}
#     endif

      /* Read the .opd section on PowerPC64 ELFv1.  */
      if (ehdr.e_machine == EM_PPC64
	  && (ehdr.e_flags & EF_PPC64_ABI) < 2
	  && shdr->sh_type == SHT_PROGBITS
	  && strcmp (name, ".opd") == 0)
	{
	  if (!elf_get_view (state, descriptor,
			     minidebuginfo_data, minidebuginfo_size,
			     shdr->sh_offset, shdr->sh_size, error_callback,
			     data, &opd_data.view))
	    goto fail;

	  opd = &opd_data;
	  opd->addr = shdr->sh_addr;
	  opd->data = (const char *) opd_data.view.data;
	  opd->size = shdr->sh_size;
	}
    }

  if (symtab_shndx == 0)
    symtab_shndx = dynsym_shndx;
  if (symtab_shndx != 0 && !debuginfo)
    {
      const b_elf_shdr *symtab_shdr;
      unsigned int strtab_shndx;
      const b_elf_shdr *strtab_shdr;
      struct elf_syminfo_data *sdata;

      symtab_shdr = &shdrs[symtab_shndx - 1];
      strtab_shndx = symtab_shdr->sh_link;
      if (strtab_shndx >= shnum)
	{
	  error_callback (data,
			  "ELF symbol table strtab link out of range", 0);
	  goto fail;
	}
      strtab_shdr = &shdrs[strtab_shndx - 1];

      if (!elf_get_view (state, descriptor,
			 minidebuginfo_data, minidebuginfo_size,
			 symtab_shdr->sh_offset, symtab_shdr->sh_size,
			 error_callback, data, &symtab_view))
	goto fail;
      symtab_view_valid = 1;

      if (!elf_get_view (state, descriptor,
			 minidebuginfo_data, minidebuginfo_size,
			 strtab_shdr->sh_offset, strtab_shdr->sh_size,
			 error_callback, data, &strtab_view))
	goto fail;
      strtab_view_valid = 1;

      sdata = ((struct elf_syminfo_data *)
	       backtrace_alloc (state, sizeof *sdata, error_callback, data));
      if (sdata == NULL)
	goto fail;

      if (!elf_initialize_syminfo (state, base_address,
				   symtab_view.data, symtab_shdr->sh_size,
				   strtab_view.data, strtab_shdr->sh_size,
				   error_callback, data, sdata, opd))
	{
	  backtrace_free (state, sdata, sizeof *sdata, error_callback, data);
	  goto fail;
	}

      /* We no longer need the symbol table, but we hold on to the
	 string table permanently.  */
      elf_release_view (state, &symtab_view, error_callback, data, use_backtrace_free_for_views);
      symtab_view_valid = 0;
      strtab_view_valid = 0;

      *found_sym = 1;

      elf_add_syminfo_data (state, sdata);
    }

  elf_release_view (state, &shdrs_view, error_callback, data, use_backtrace_free_for_views);
  shdrs_view_valid = 0;
  elf_release_view (state, &names_view, error_callback, data, use_backtrace_free_for_views);
  names_view_valid = 0;

  /* If the debug info is in a separate file, read that one instead.  */

  if (buildid_data != NULL)
    {
      int d;

      d = elf_open_debugfile_by_buildid (state, buildid_data, buildid_size,
					 error_callback, data);
      if (d >= 0)
	{
	  int ret;

	  elf_release_view (state, &buildid_view, error_callback, data,
			    use_backtrace_free_for_views);
	  if (debuglink_view_valid)
	    elf_release_view (state, &debuglink_view, error_callback,
			      data, use_backtrace_free_for_views);
	  if (debugaltlink_view_valid)
	    elf_release_view (state, &debugaltlink_view, error_callback,
			      data, use_backtrace_free_for_views);
	  if (gnu_debugdata_valid)
	    elf_release_view (state, &gnu_debugdata, error_callback,
			      data, use_backtrace_free_for_views);
	  ret = elf_add (state, "", d, base_address, error_callback, data,
			 fileline_fn, found_sym, found_dwarf, NULL, 0, 1, NULL,
			 0, NULL, 0);
	  if (ret < 0)
	    backtrace_close (d, error_callback, data);
	  else
	    backtrace_close (descriptor, error_callback, data);
	  return ret;
	}
    }

  if (buildid_view_valid)
    {
      elf_release_view (state, &buildid_view, error_callback,
			data, use_backtrace_free_for_views);
      buildid_view_valid = 0;
    }

  if (opd)
    {
      elf_release_view (state, &opd->view, error_callback,
			data, use_backtrace_free_for_views);
      opd = NULL;
    }

  if (debuglink_name != NULL)
    {
      int d;

      d = elf_open_debugfile_by_debuglink (state, filename, debuglink_name,
					   debuglink_crc, error_callback,
					   data);
      if (d >= 0)
	{
	  int ret;

	  elf_release_view (state, &debuglink_view, error_callback,
			    data, use_backtrace_free_for_views);
	  if (debugaltlink_view_valid)
	    elf_release_view (state, &debugaltlink_view, error_callback,
			      data, use_backtrace_free_for_views);
	  if (gnu_debugdata_valid)
	    elf_release_view(state, &gnu_debugdata, error_callback,
			     data, use_backtrace_free_for_views);
	  ret = elf_add (state, "", d, base_address, error_callback, data,
			 fileline_fn, found_sym, found_dwarf, NULL, 0, 1, NULL,
			 0, NULL, 0);
	  if (ret < 0)
	    backtrace_close (d, error_callback, data);
	  else
	    backtrace_close(descriptor, error_callback, data);
	  return ret;
	}
    }

  if (debuglink_view_valid)
    {
      elf_release_view (state, &debuglink_view, error_callback,
			data, use_backtrace_free_for_views);
      debuglink_view_valid = 0;
    }

  /* If the debug info is in a MiniDebugInfo format */

  if (gnu_debugdata_data != NULL)
    {
#     ifdef MINI_DEBUG_INFO
      struct backtrace_vector uncompressed;
      int ret;

      if (!elf_uncompress_lzma_gnu_debugdata (state, error_callback, data,
					      gnu_debugdata_data, gnu_debugdata_size,
					      &uncompressed)) {
	goto fail;
      }

      elf_release_view (state, &gnu_debugdata, error_callback,
		        data, use_backtrace_free_for_views);
      if (debugaltlink_view_valid)
	elf_release_view (state, &debugaltlink_view, error_callback,
			  data, use_backtrace_free_for_views);

      ret = elf_add (state, filename, -1, base_address, error_callback, data,
		     fileline_fn, found_sym, found_dwarf, fileline_entry, 0, 1, NULL,
		     0, uncompressed.base, uncompressed.size);
      backtrace_vector_free (state, &uncompressed, error_callback, data);
      if (ret >= 0)
	backtrace_close (descriptor, error_callback, data);
      return ret;
#     endif
    }

  if (gnu_debugdata_valid)
    {
      elf_release_view (state, &gnu_debugdata, error_callback,
		        data, use_backtrace_free_for_views);
      gnu_debugdata_valid = 0;
    }

  struct dwarf_data *fileline_altlink = NULL;
  if (debugaltlink_name != NULL)
    {
      int d;

      d = elf_open_debugfile_by_debuglink (state, filename, debugaltlink_name,
					   0, error_callback, data);
      if (d >= 0)
	{
	  int ret;

	  ret = elf_add (state, filename, d, base_address, error_callback, data,
			 fileline_fn, found_sym, found_dwarf, &fileline_altlink,
			 0, 1, debugaltlink_buildid_data,
			 debugaltlink_buildid_size, NULL, 0);
	  elf_release_view (state, &debugaltlink_view, error_callback,
			    data, use_backtrace_free_for_views);
	  debugaltlink_view_valid = 0;
	  if (ret < 0)
	    {
	      backtrace_close (d, error_callback, data);
	      return ret;
	    }
	}
    }

  if (debugaltlink_view_valid)
    {
      elf_release_view (state, &debugaltlink_view, error_callback,
			data, use_backtrace_free_for_views);
      debugaltlink_view_valid = 0;
    }

  /* Read all the debug sections in a single view, since they are
     probably adjacent in the file.  If any of sections are
     uncompressed, we never release this view.  */

  min_offset = 0;
  max_offset = 0;
  debug_size = 0;
  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      off_t end;

      if (sections[i].size != 0)
	{
	  if (min_offset == 0 || sections[i].offset < min_offset)
	    min_offset = sections[i].offset;
	  end = sections[i].offset + sections[i].size;
	  if (end > max_offset)
	    max_offset = end;
	  debug_size += sections[i].size;
	}
      if (zsections[i].size != 0)
	{
	  if (min_offset == 0 || zsections[i].offset < min_offset)
	    min_offset = zsections[i].offset;
	  end = zsections[i].offset + zsections[i].size;
	  if (end > max_offset)
	    max_offset = end;
	  debug_size += zsections[i].size;
	}
    }
  if (min_offset == 0 || max_offset == 0)
    {
      if (descriptor >= 0 && !backtrace_close (descriptor, error_callback, data))
	goto fail;
      return 1;
    }

  /* If the total debug section size is large, assume that there are
     gaps between the sections, and read them individually.  */

  if (max_offset - min_offset < 0x20000000
      || max_offset - min_offset < debug_size + 0x10000)
    {
      if (!elf_get_view (state, descriptor,
			 minidebuginfo_data, minidebuginfo_size,
			 min_offset, max_offset - min_offset,
			 error_callback, data, &debug_view))
	goto fail;
      debug_view_valid = 1;
    }
  else
    {
      memset (&split_debug_view[0], 0, sizeof split_debug_view);
      for (i = 0; i < (int) DEBUG_MAX; ++i)
	{
	  struct debug_section_info *dsec;

	  if (sections[i].size != 0)
	    dsec = &sections[i];
	  else if (zsections[i].size != 0)
	    dsec = &zsections[i];
	  else
	    continue;

	  if (!elf_get_view (state, descriptor,
			     minidebuginfo_data, minidebuginfo_size,
			     dsec->offset, dsec->size, error_callback,
			     data, &split_debug_view[i]))
	    goto fail;
	  split_debug_view_valid[i] = 1;

	  if (sections[i].size != 0)
	    sections[i].data = ((const unsigned char *)
				split_debug_view[i].data);
	  else
	    zsections[i].data = ((const unsigned char *)
				 split_debug_view[i].data);
	}
    }

  /* We've read all we need from the executable.  */
  if (descriptor >= 0 && !backtrace_close (descriptor, error_callback, data))
    goto fail;
  descriptor = -1;

  using_debug_view = 0;
  if (debug_view_valid)
    {
      for (i = 0; i < (int) DEBUG_MAX; ++i)
	{
	  if (sections[i].size == 0)
	    sections[i].data = NULL;
	  else
	    {
	      sections[i].data = ((const unsigned char *) debug_view.data
				  + (sections[i].offset - min_offset));
	      ++using_debug_view;
	    }

	  if (zsections[i].size == 0)
	    zsections[i].data = NULL;
	  else
	    zsections[i].data = ((const unsigned char *) debug_view.data
				 + (zsections[i].offset - min_offset));
	}
    }

  /* Uncompress the old format (--compress-debug-sections=zlib-gnu).  */

  zdebug_table = NULL;
  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      if (sections[i].size == 0 && zsections[i].size > 0)
	{
	  unsigned char *uncompressed_data;
	  size_t uncompressed_size;

	  if (zdebug_table == NULL)
	    {
	      zdebug_table = ((uint16_t *)
			      backtrace_alloc (state, ZDEBUG_TABLE_SIZE,
					       error_callback, data));
	      if (zdebug_table == NULL)
		goto fail;
	    }

	  uncompressed_data = NULL;
	  uncompressed_size = 0;
	  if (!elf_uncompress_zdebug (state, zsections[i].data,
				      zsections[i].size, zdebug_table,
				      error_callback, data,
				      &uncompressed_data, &uncompressed_size))
	    goto fail;
	  sections[i].data = uncompressed_data;
	  sections[i].size = uncompressed_size;
	  sections[i].compressed = 0;

	  if (split_debug_view_valid[i])
	    {
	      elf_release_view (state, &split_debug_view[i],
				error_callback, data, use_backtrace_free_for_views);
	      split_debug_view_valid[i] = 0;
	    }
	}
    }

  /* Uncompress the official ELF format
     (--compress-debug-sections=zlib-gabi).  */
  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      unsigned char *uncompressed_data;
      size_t uncompressed_size;

      if (sections[i].size == 0 || !sections[i].compressed)
	continue;

      if (zdebug_table == NULL)
	{
	  zdebug_table = ((uint16_t *)
			  backtrace_alloc (state, ZDEBUG_TABLE_SIZE,
					   error_callback, data));
	  if (zdebug_table == NULL)
	    goto fail;
	}

      uncompressed_data = NULL;
      uncompressed_size = 0;
      if (!elf_uncompress_chdr (state, sections[i].data, sections[i].size,
				zdebug_table, error_callback, data,
				&uncompressed_data, &uncompressed_size))
	goto fail;
      sections[i].data = uncompressed_data;
      sections[i].size = uncompressed_size;
      sections[i].compressed = 0;

      if (debug_view_valid)
	--using_debug_view;
      else if (split_debug_view_valid[i])
	{
	  elf_release_view (state, &split_debug_view[i],
			    error_callback, data, use_backtrace_free_for_views);
	  split_debug_view_valid[i] = 0;
	}
    }

  if (zdebug_table != NULL)
    backtrace_free (state, zdebug_table, ZDEBUG_TABLE_SIZE,
		    error_callback, data);

  if (debug_view_valid && using_debug_view == 0)
    {
      elf_release_view (state, &debug_view, error_callback,
			data, use_backtrace_free_for_views);
      debug_view_valid = 0;
    }

  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      dwarf_sections.data[i] = sections[i].data;
      dwarf_sections.size[i] = sections[i].size;
    }

  if (!backtrace_dwarf_add (state, base_address, &dwarf_sections,
			    ehdr.e_ident[EI_DATA] == ELFDATA2MSB,
			    fileline_altlink,
			    error_callback, data, fileline_fn,
			    fileline_entry))
    goto fail;

  *found_dwarf = 1;

  return 1;

 fail:
  if (shdrs_view_valid)
    elf_release_view (state, &shdrs_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (names_view_valid)
    elf_release_view (state, &names_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (symtab_view_valid)
    elf_release_view (state, &symtab_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (strtab_view_valid)
    elf_release_view (state, &strtab_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (debuglink_view_valid)
    elf_release_view (state, &debuglink_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (debugaltlink_view_valid)
    elf_release_view (state, &debugaltlink_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (buildid_view_valid)
    elf_release_view (state, &buildid_view, error_callback,
		      data, use_backtrace_free_for_views);
  if (debug_view_valid)
    elf_release_view (state, &debug_view, error_callback,
		      data, use_backtrace_free_for_views);
  for (i = 0; i < (int) DEBUG_MAX; ++i)
    {
      if (split_debug_view_valid[i])
	elf_release_view (state, &split_debug_view[i],
			  error_callback, data,
			  use_backtrace_free_for_views);
    }
  if (opd)
    elf_release_view (state, &opd->view, error_callback,
		      data, use_backtrace_free_for_views);
  if (descriptor != -1)
    backtrace_close (descriptor, error_callback, data);
  return 0;
}

/* Data passed to phdr_callback.  */

struct phdr_data
{
  struct backtrace_state *state;
  backtrace_error_callback error_callback;
  void *data;
  fileline *fileline_fn;
  int *found_sym;
  int *found_dwarf;
  const char *exe_filename;
  int exe_descriptor;
};

/* Callback passed to dl_iterate_phdr.  Load debug info from shared
   libraries.  */

static int
#ifdef __i386__
__attribute__ ((__force_align_arg_pointer__))
#endif
phdr_callback (struct dl_phdr_info *info, size_t size ATTRIBUTE_UNUSED,
	       void *pdata)
{
  struct phdr_data *pd = (struct phdr_data *) pdata;
  const char *filename;
  int descriptor;
  int does_not_exist;
  fileline elf_fileline_fn;
  int found_dwarf;

  /* There is not much we can do if we don't have the module name,
     unless executable is ET_DYN, where we expect the very first
     phdr_callback to be for the PIE.  */
  if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0')
    {
      if (pd->exe_descriptor == -1)
	return 0;
      filename = pd->exe_filename;
      descriptor = pd->exe_descriptor;
      pd->exe_descriptor = -1;
    }
  else
    {
      if (pd->exe_descriptor != -1)
	{
	  backtrace_close (pd->exe_descriptor, pd->error_callback, pd->data);
	  pd->exe_descriptor = -1;
	}

      filename = info->dlpi_name;
      descriptor = backtrace_open (info->dlpi_name, pd->error_callback,
				   pd->data, &does_not_exist);
      if (descriptor < 0)
	return 0;
    }

  if (elf_add (pd->state, filename, descriptor, info->dlpi_addr,
	       pd->error_callback, pd->data, &elf_fileline_fn, pd->found_sym,
	       &found_dwarf, NULL, 0, 0, NULL, 0, NULL, 0))
    {
      if (found_dwarf)
	{
	  *pd->found_dwarf = 1;
	  *pd->fileline_fn = elf_fileline_fn;
	}
    }

  return 0;
}

/* Initialize the backtrace data we need from an ELF executable.  At
   the ELF level, all we need to do is find the debug info
   sections.  */

int
backtrace_initialize (struct backtrace_state *state, const char *filename,
		      int descriptor, backtrace_error_callback error_callback,
		      void *data, fileline *fileline_fn)
{
  int ret;
  int found_sym;
  int found_dwarf;
  fileline elf_fileline_fn = elf_nodebug;
  struct phdr_data pd;

  ret = elf_add (state, filename, descriptor, 0, error_callback, data,
		 &elf_fileline_fn, &found_sym, &found_dwarf, NULL, 1, 0, NULL,
		 0, NULL, 0);
  if (!ret)
    return 0;

  pd.state = state;
  pd.error_callback = error_callback;
  pd.data = data;
  pd.fileline_fn = &elf_fileline_fn;
  pd.found_sym = &found_sym;
  pd.found_dwarf = &found_dwarf;
  pd.exe_filename = filename;
  pd.exe_descriptor = ret < 0 ? descriptor : -1;

  dl_iterate_phdr (phdr_callback, (void *) &pd);

  if (!state->threaded)
    {
      if (found_sym)
	state->syminfo_fn = elf_syminfo;
      else if (state->syminfo_fn == NULL)
	state->syminfo_fn = elf_nosyms;
    }
  else
    {
      if (found_sym)
	backtrace_atomic_store_pointer (&state->syminfo_fn, elf_syminfo);
      else
	(void) __sync_bool_compare_and_swap (&state->syminfo_fn, NULL,
					     elf_nosyms);
    }

  if (!state->threaded)
    *fileline_fn = state->fileline_fn;
  else
    *fileline_fn = backtrace_atomic_load_pointer (&state->fileline_fn);

  if (*fileline_fn == NULL || *fileline_fn == elf_nodebug)
    *fileline_fn = elf_fileline_fn;

  return 1;
}
