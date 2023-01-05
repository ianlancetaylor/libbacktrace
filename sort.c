/* sort.c -- Sort without allocating memory
   Copyright (C) 2012-2021 Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Google.

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

#include <stddef.h>
#include <sys/types.h>

#include "backtrace.h"
#include "internal.h"

/* The GNU glibc version of qsort allocates memory, which we must not
   do if we are invoked by a signal handler.  So provide our own
   sort.  */

static void
swap (char *a, char *b, size_t size)
{
  size_t i;

  for (i = 0; i < size; i++, a++, b++)
    {
      char t;

      t = *a;
      *a = *b;
      *b = t;
    }
}

void
backtrace_qsort (void *basearg, size_t count, size_t size,
		 int (*compar) (const void *, const void *))
{
  char *base = (char *) basearg;
  char *cur;
  size_t i, d, dist;

  if (count < 2)
    return;

  /* Shell sort doesn't require recursion. It is comparable to naive
     qsort on small arrays and just twice slower on million items. */
  dist = count;
  do
    {
      dist = (dist / 8 * 3) | 1;
      d = dist * size;
      for (i = dist; i < count; i++)
	for (cur = base + i*size - d; cur >= base; cur -= d)
	  {
	    if ((*compar) (cur, cur + d) <= 0)
	      break;
	    swap (cur, cur + d, size);
	  }
    }
  while (dist != 1);
}
