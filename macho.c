/* macho.c -- Get debug data from an Mach-O file for backtraces.
   Copyright (C) 2017 John Colanduoni.

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

#include <sys/types.h>
#include <sys/syslimits.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <uuid/uuid.h>
#include <dirent.h>
#include <stdlib.h>

#include "backtrace.h"
#include "internal.h"

struct macho_commands_view
{
    struct backtrace_view view;
    uint32_t commands_count;
    uint32_t commands_total_size;
    int bytes_swapped;
};

enum debug_section
{
    DEBUG_INFO,
    DEBUG_LINE,
    DEBUG_ABBREV,
    DEBUG_RANGES,
    DEBUG_STR,
    DEBUG_MAX
};

static const char *const debug_section_names[DEBUG_MAX] =
    {
        "__debug_info",
        "__debug_line",
        "__debug_abbrev",
        "__debug_ranges",
        "__debug_str"
    };

struct found_dwarf_section
{
    uint32_t file_offset;
    uint64_t file_size;
    const unsigned char *data;
};

uint32_t
macho_file_to_host_u32 (int file_bytes_swapped, uint32_t input)
{
  if (file_bytes_swapped)
    {
      return ((input >> 24) & 0x000000FF)
             | ((input >> 8) & 0x0000FF00)
             | ((input << 8) & 0x00FF0000)
             | ((input << 24) & 0xFF000000);
    }
  else
    {
      return input;
    }
}

uint64_t
macho_file_to_host_u64 (int file_bytes_swapped, uint64_t input)
{
  if (file_bytes_swapped)
    {
      return macho_file_to_host_u32 (file_bytes_swapped,
                                     (uint32_t) (input >> 32))
             | (((uint64_t) macho_file_to_host_u32 (file_bytes_swapped,
                                                    (uint32_t) input)) << 32);
    }
  else
    {
      return input;
    }
}

int
macho_get_commands (struct backtrace_state *state, int descriptor,
                    backtrace_error_callback error_callback,
                    void *data, struct macho_commands_view *commands_view)
{
  int file_bits;
  uint32_t commands_offset;

  int ret = 0;
  struct backtrace_view file_header_view;
  int file_header_view_valid = 0;

  if (!backtrace_get_view (state, descriptor, 0, sizeof (struct mach_header_64),
                           error_callback, data, &file_header_view))
    goto end;
  file_header_view_valid = 1;

  switch (*(uint32_t *) file_header_view.data)
    {
      case MH_MAGIC:
        file_bits = 32;
      commands_view->bytes_swapped = 0;
      break;
      case MH_CIGAM:
        file_bits = 32;
      commands_view->bytes_swapped = 1;
      break;
      case MH_MAGIC_64:
        file_bits = 64;
      commands_view->bytes_swapped = 0;
      break;
      case MH_CIGAM_64:
        file_bits = 64;
      commands_view->bytes_swapped = 1;
      break;
      default:
        error_callback (data, "executable file is not a Mach-O image", 0);
      goto end;
    }

  if (file_bits == 64)
    {
      const struct mach_header_64 *file_header = file_header_view.data;
      commands_view->commands_count =
          macho_file_to_host_u32 (commands_view->bytes_swapped,
                                  file_header->ncmds);
      commands_view->commands_total_size =
          macho_file_to_host_u32 (commands_view->bytes_swapped,
                                  file_header->sizeofcmds);
      commands_offset = sizeof (struct mach_header_64);
    }
  else
    { /* file_bits == 32 */
      const struct mach_header *file_header = file_header_view.data;
      commands_view->commands_count =
          macho_file_to_host_u32 (commands_view->bytes_swapped,
                                  file_header->ncmds);
      commands_view->commands_total_size =
          macho_file_to_host_u32 (commands_view->bytes_swapped,
                                  file_header->sizeofcmds);
      commands_offset = sizeof (struct mach_header);
    }

  if (!backtrace_get_view (state, descriptor, commands_offset,
                           commands_view->commands_total_size, error_callback,
                           data, &commands_view->view))
    goto end;

  ret = 1;

end:
  if (file_header_view_valid)
    backtrace_release_view (state, &file_header_view, error_callback, data);
  return ret;
}

int
macho_get_uuid (struct backtrace_state *state ATTRIBUTE_UNUSED, int descriptor ATTRIBUTE_UNUSED,
                backtrace_error_callback error_callback,
                void *data, struct macho_commands_view *commands_view,
                uuid_t *uuid)
{
  size_t offset = 0;

  for (uint32_t i = 0; i < commands_view->commands_count; i++)
    {
      if (offset + sizeof (struct load_command)
          > commands_view->commands_total_size)
        {
          error_callback (data, "executable file is truncated", 0);
          return 0;
        }

      const struct load_command *raw_command =
          commands_view->view.data + offset;
      struct load_command command;
      command.cmd = macho_file_to_host_u32 (commands_view->bytes_swapped,
                                            raw_command->cmd);
      command.cmdsize = macho_file_to_host_u32 (commands_view->bytes_swapped,
                                                raw_command->cmdsize);

      if (command.cmd == LC_UUID)
        {
          if (offset + sizeof (struct uuid_command)
              > commands_view->commands_total_size)
            {
              error_callback (data, "executable file is truncated", 0);
              return 0;
            }

          const struct uuid_command *uuid_command =
              (struct uuid_command *) raw_command;
          memcpy (uuid, uuid_command->uuid, sizeof (uuid_t));
          return 1;
        }

      offset += command.cmdsize;
    }

  error_callback (data, "executable file is missing an identifying uuid", 0);
  return 0;
}

/* Returns the base address of a Mach-O image, as encoded in the file header.
 * WARNING: This does not take ASLR into account, which is ubiquitous on recent
 * Darwin platforms.
 */
int
macho_get_base (struct backtrace_state *state ATTRIBUTE_UNUSED, int descriptor ATTRIBUTE_UNUSED,
                backtrace_error_callback error_callback,
                void *data, struct macho_commands_view *commands_view,
                uint64_t *base_address)
{
  size_t offset = 0;
  uint64_t text_vmaddr;
  uint64_t text_fileoff;

  for (uint32_t i = 0; i < commands_view->commands_count; i++)
    {
      if (offset + sizeof (struct load_command)
          > commands_view->commands_total_size)
        {
          error_callback (data, "executable file is truncated", 0);
          return 0;
        }

      const struct load_command *raw_command =
          commands_view->view.data + offset;
      struct load_command command;
      command.cmd = macho_file_to_host_u32 (commands_view->bytes_swapped,
                                            raw_command->cmd);
      command.cmdsize = macho_file_to_host_u32 (commands_view->bytes_swapped,
                                                raw_command->cmdsize);

      if (command.cmd == LC_SEGMENT)
        {
          if (offset + sizeof (struct segment_command)
              > commands_view->commands_total_size)
            {
              error_callback (data, "executable file is truncated", 0);
              return 0;
            }

          const struct segment_command *raw_segment =
              (const struct segment_command *) raw_command;

          if (strncmp (raw_segment->segname, "__TEXT",
                       sizeof (raw_segment->segname)) == 0)
            {
              text_vmaddr = macho_file_to_host_u32 (
                  commands_view->bytes_swapped, raw_segment->vmaddr);
              text_fileoff = macho_file_to_host_u32 (
                  commands_view->bytes_swapped, raw_segment->fileoff);
              *base_address = text_vmaddr - text_fileoff;
              return 1;
            }
        }
      else if (command.cmd == LC_SEGMENT_64)
        {
          if (offset + sizeof (struct segment_command_64)
              > commands_view->commands_total_size)
            {
              error_callback (data, "executable file is truncated", 0);
              return 0;
            }

          struct segment_command *raw_segment =
              (struct segment_command *) raw_command;

          if (strncmp (raw_segment->segname, "__TEXT",
                       sizeof (raw_segment->segname)) == 0)
            {
              text_vmaddr = macho_file_to_host_u64 (
                  commands_view->bytes_swapped, raw_segment->vmaddr);
              text_fileoff = macho_file_to_host_u64 (
                  commands_view->bytes_swapped, raw_segment->fileoff);
              *base_address = text_vmaddr - text_fileoff;
              return 1;
            }
        }

      offset += command.cmdsize;
    }

  error_callback (data, "executable file is missing a valid __TEXT segment", 0);
  return 0;
}

int
macho_try_dwarf (struct backtrace_state *state,
                 backtrace_error_callback error_callback,
                 void *data, fileline *fileline_fn, uuid_t *executable_uuid,
                 uintptr_t base_address, char *dwarf_filename)
{
  uuid_t dwarf_uuid;

  int ret = 0;
  int dwarf_descriptor;
  int dwarf_descriptor_valid = 0;
  struct macho_commands_view commands_view;
  int commands_view_valid = 0;
  struct backtrace_view dwarf_view;
  int dwarf_view_valid = 0;
  size_t offset = 0;

  if ((dwarf_descriptor = backtrace_open (dwarf_filename, error_callback,
                                          data, NULL)) == 0)
    goto end;
  dwarf_descriptor_valid = 1;

  if (!macho_get_commands (state, dwarf_descriptor, error_callback, data,
                           &commands_view))
    goto end;
  commands_view_valid = 1;

  // Get dSYM UUID and compare
  if (!macho_get_uuid (state, dwarf_descriptor, error_callback, data,
                       &commands_view, &dwarf_uuid))
    {
      error_callback (data, "dSYM file is missing an identifying uuid", 0);
      goto end;
    }
  if (memcmp (executable_uuid, &dwarf_uuid, sizeof (uuid_t)) != 0)
    goto end;

  // Get DWARF sections
  struct found_dwarf_section dwarf_sections[DEBUG_MAX];
  uint64_t min_dwarf_offset = 0;
  uint64_t max_dwarf_offset = 0;
  memset (dwarf_sections, 0, sizeof (dwarf_sections));
  offset = 0;
  for (uint32_t i = 0; i < commands_view.commands_count; i++)
    {
      if (offset + sizeof (struct load_command)
          > commands_view.commands_total_size)
        {
          error_callback (data, "dSYM file is truncated", 0);
          goto end;
        }

      const struct load_command *raw_command = commands_view.view.data + offset;
      struct load_command command;
      command.cmd = macho_file_to_host_u32 (commands_view.bytes_swapped,
                                            raw_command->cmd);
      command.cmdsize = macho_file_to_host_u32 (commands_view.bytes_swapped,
                                                raw_command->cmdsize);

      if (command.cmd == LC_SEGMENT || command.cmd == LC_SEGMENT_64)
        {
          uint32_t section_count;
          size_t section_offset;

          if (command.cmd == LC_SEGMENT)
            {
              if (offset + sizeof (struct segment_command)
                  > commands_view.commands_total_size)
                {
                  error_callback (data, "dSYM file is truncated", 0);
                  goto end;
                }

              const struct segment_command *raw_segment =
                  (const struct segment_command *) raw_command;

              if (strncmp (raw_segment->segname, "__DWARF",
                           sizeof (raw_segment->segname)) == 0)
                {
                  section_count = macho_file_to_host_u32 (
                      commands_view.bytes_swapped,
                      raw_segment->nsects);

                  section_offset = offset + sizeof (struct segment_command);

                  // Search sections for relevant DWARF section names
                  for (uint32_t j = 0; j < section_count; j++)
                    {
                      if (section_offset + sizeof (struct section) >
                          commands_view.commands_total_size)
                        {
                          error_callback (data, "dSYM file is truncated", 0);
                          goto end;
                        }

                      const struct section *raw_section =
                          commands_view.view.data + section_offset;

                      for (int k = 0; k < DEBUG_MAX; k++)
                        {
                          if (strncmp (raw_section->sectname,
                                       debug_section_names[k],
                                       sizeof (raw_section->sectname)) == 0)
                            {
                              dwarf_sections[k].file_offset =
                                  macho_file_to_host_u32 (
                                      commands_view.bytes_swapped,
                                      raw_section->offset);
                              dwarf_sections[k].file_size = macho_file_to_host_u32 (
                                  commands_view.bytes_swapped,
                                  raw_section->size);

                              if (min_dwarf_offset == 0 ||
                                  dwarf_sections[k].file_offset <
                                  min_dwarf_offset)
                                min_dwarf_offset = dwarf_sections[k].file_offset;

                              uint64_t dwarf_section_end =
                                  dwarf_sections[k].file_offset +
                                  dwarf_sections[k].file_size;
                              if (dwarf_section_end > max_dwarf_offset)
                                max_dwarf_offset = dwarf_section_end;

                              break;
                            }
                        }

                      section_offset += sizeof (struct section);
                    }
                }
            }
          else
            { /* command.cmd == LC_SEGMENT_64 */
              if (offset + sizeof (struct segment_command_64)
                  > commands_view.commands_total_size)
                {
                  error_callback (data, "dSYM file is truncated", 0);
                  goto end;
                }

              const struct segment_command_64 *raw_segment =
                  (const struct segment_command_64 *) raw_command;

              if (strncmp (raw_segment->segname, "__DWARF",
                           sizeof (raw_segment->segname)) == 0)
                {
                  section_count = macho_file_to_host_u32 (
                      commands_view.bytes_swapped,
                      raw_segment->nsects);

                  section_offset = offset + sizeof (struct segment_command_64);

                  // Search sections for relevant DWARF section names
                  for (uint32_t j = 0; j < section_count; j++)
                    {
                      if (section_offset + sizeof (struct section_64) >
                          commands_view.commands_total_size)
                        {
                          error_callback (data, "dSYM file is truncated", 0);
                          goto end;
                        }

                      const struct section_64 *raw_section =
                          commands_view.view.data + section_offset;

                      for (int k = 0; k < DEBUG_MAX; k++)
                        {
                          if (strncmp (raw_section->sectname,
                                       debug_section_names[k],
                                       sizeof (raw_section->sectname)) == 0)
                            {
                              dwarf_sections[k].file_offset =
                                  macho_file_to_host_u32 (
                                      commands_view.bytes_swapped,
                                      raw_section->offset);
                              dwarf_sections[k].file_size = macho_file_to_host_u64 (
                                  commands_view.bytes_swapped,
                                  raw_section->size);

                              if (min_dwarf_offset == 0 ||
                                  dwarf_sections[k].file_offset <
                                  min_dwarf_offset)
                                min_dwarf_offset = dwarf_sections[k].file_offset;

                              uint64_t dwarf_section_end =
                                  dwarf_sections[k].file_offset +
                                  dwarf_sections[k].file_size;
                              if (dwarf_section_end > max_dwarf_offset)
                                max_dwarf_offset = dwarf_section_end;

                              break;
                            }
                        }

                      section_offset += sizeof (struct section_64);
                    }
                }
            }
        }

      offset += command.cmdsize;
    }

  if (max_dwarf_offset == 0)
    goto end;

  if (!backtrace_get_view (state, dwarf_descriptor, min_dwarf_offset,
                           max_dwarf_offset - min_dwarf_offset, error_callback,
                           data, &dwarf_view))
    goto end;
  dwarf_view_valid = 1;

  for (int i = 0; i < DEBUG_MAX; i++)
    {
      if (dwarf_sections[i].file_offset == 0)
        dwarf_sections[i].data = NULL;
      else
        dwarf_sections[i].data =
            dwarf_view.data + dwarf_sections[i].file_offset - min_dwarf_offset;
    }

  if (!backtrace_dwarf_add (state, base_address,
                            dwarf_sections[DEBUG_INFO].data,
                            dwarf_sections[DEBUG_INFO].file_size,
                            dwarf_sections[DEBUG_LINE].data,
                            dwarf_sections[DEBUG_LINE].file_size,
                            dwarf_sections[DEBUG_ABBREV].data,
                            dwarf_sections[DEBUG_ABBREV].file_size,
                            dwarf_sections[DEBUG_RANGES].data,
                            dwarf_sections[DEBUG_RANGES].file_size,
                            dwarf_sections[DEBUG_STR].data,
                            dwarf_sections[DEBUG_STR].file_size,
                            (__DARWIN_BYTE_ORDER == __DARWIN_BIG_ENDIAN) ^
                            commands_view.bytes_swapped,
                            error_callback, data, fileline_fn))
    goto end;

  dwarf_descriptor_valid = 0; // Don't release the DWARF view because it is
  // still in use
  ret = 1;

end:
  if (dwarf_descriptor_valid)
    backtrace_close (dwarf_descriptor, error_callback, data);
  if (commands_view_valid)
    backtrace_release_view (state, &commands_view.view, error_callback,
                            data);
  if (dwarf_view_valid)
    backtrace_release_view (state, &dwarf_view, error_callback, data);
  return ret;
}

int
macho_try_dsym (struct backtrace_state *state,
                backtrace_error_callback error_callback,
                void *data, fileline *fileline_fn, uuid_t *executable_uuid,
                uintptr_t base_address, char *dsym_filename)
{
  int ret = 0;
  char dwarf_image_dir_path[PATH_MAX];
  DIR *dwarf_image_dir;
  int dwarf_image_dir_valid = 0;
  struct dirent *directory_entry;
  char dwarf_filename[PATH_MAX];

  strncpy(dwarf_image_dir_path, dsym_filename, PATH_MAX);
  strncat(dwarf_image_dir_path, "/Contents/Resources/DWARF", PATH_MAX);

  if (!(dwarf_image_dir = opendir (dwarf_image_dir_path)))
    {
      error_callback (data, "could not open DWARF directory in dSYM",
                      0);
      goto end;
    }
  dwarf_image_dir_valid = 1;

  while ((directory_entry = readdir (dwarf_image_dir)))
    {
      if (directory_entry->d_type != DT_REG)
        continue;

      strncpy(dwarf_filename, dwarf_image_dir_path, PATH_MAX);
      strncat(dwarf_filename, "/", PATH_MAX);
      strncat(dwarf_filename, directory_entry->d_name, PATH_MAX);

      if (macho_try_dwarf (state, error_callback, data, fileline_fn,
                           executable_uuid, base_address, dwarf_filename))
        {
          ret = 1;
          goto end;
        }
    }

end:
  if (dwarf_image_dir_valid)
    closedir (dwarf_image_dir);
  return ret;
}

int
backtrace_initialize (struct backtrace_state *state, int descriptor,
                      backtrace_error_callback error_callback,
                      void *data, fileline *fileline_fn)
{
  uuid_t image_uuid;
  uint64_t image_file_base_address;
  uint64_t image_actual_base_address = 0;

  int ret = 0;
  char executable_full_path[PATH_MAX];
  struct macho_commands_view commands_view;
  int commands_view_valid = 0;
  uint32_t dyld_image_count;
  char executable_dirname[PATH_MAX];
  size_t filename_len;
  DIR *executable_dir = NULL;
  int executable_dir_valid = 0;
  struct dirent *directory_entry;
  char dsym_full_path[PATH_MAX];

  // Get full image filename
  realpath (state->filename, executable_full_path);

  // Find Mach-O commands list
  if (!macho_get_commands (state, descriptor, error_callback, data,
                           &commands_view))
    goto end;
  commands_view_valid = 1;

  // First we need to get the uuid of our file so we can hunt down the correct
  // dSYM
  if (!macho_get_uuid (state, descriptor, error_callback, data, &commands_view,
                       &image_uuid))
    goto end;

  // Now we need to find the in memory base address. Step one is to find out
  // what the executable thinks the base address is
  if (!macho_get_base (state, descriptor, error_callback, data, &commands_view,
                       &image_file_base_address))
    goto end;

  // Add ASLR offset
  dyld_image_count = _dyld_image_count ();
  for (uint32_t i = 0; i < dyld_image_count; i++)
    {
      char dyld_image_full_path[PATH_MAX];
      realpath (_dyld_get_image_name (i), dyld_image_full_path);

      if (strncmp (dyld_image_full_path, executable_full_path, PATH_MAX) == 0)
        {
          image_actual_base_address =
              image_file_base_address + _dyld_get_image_vmaddr_slide (i);
          break;
        }
    }

  if (image_actual_base_address == 0)
    {
      error_callback (data, "executable file is not loaded", 0);
      goto end;
    }

  // Look for dSYM in our executable's directory
  strncpy(executable_dirname, executable_full_path, PATH_MAX);
  filename_len = strlen (executable_dirname);
  for (ssize_t i = filename_len - 1; i >= 0; i--)
    {
      if (executable_dirname[i] == '/')
        {
          executable_dirname[i] = '\0';
          break;
        }
      else if (i == 0)
        {
          executable_dirname[0] = '.';
          executable_dirname[1] = '\0';
          break;
        }
    }

  if (!(executable_dir = opendir (executable_dirname)))
    {
      error_callback (data, "could not open directory containing executable",
                      0);
      goto end;
    }
  executable_dir_valid = 1;

  static const char *extension = ".dSYM";
  size_t extension_len = strlen (extension);
  while ((directory_entry = readdir (executable_dir)))
    {
      if (directory_entry->d_namlen < extension_len)
        continue;
      if (strncasecmp (directory_entry->d_name + directory_entry->d_namlen
                       - extension_len, extension, extension_len) == 0)
        {
          // Found a dSYM
          strncpy(dsym_full_path, executable_dirname, PATH_MAX);
          strncat(dsym_full_path, "/", PATH_MAX);
          strncat(dsym_full_path, directory_entry->d_name, PATH_MAX);
          if (macho_try_dsym (state, error_callback, data,
                              fileline_fn, &image_uuid,
                              image_actual_base_address, dsym_full_path))
            {
              ret = 1;
              goto end;
            }
        }
    }

  error_callback (data, "executable file is missing an associated dSYM", -1);
  ret = 0;

end:
  if (commands_view_valid)
    backtrace_release_view (state, &commands_view.view, error_callback,
                            data);
  if (executable_dir_valid)
    closedir (executable_dir);
  return ret;
}

