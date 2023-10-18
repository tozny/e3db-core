/*
 * mem.c --- Memory management utilities.
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO: Allow the client to override the default OOM handler.
static void default_oom_handler(size_t size)
{
  fprintf(stderr, "Fatal: Request for %zd bytes of memory failed.\n", size);
  abort();
}

void *xmalloc(size_t size)
{
  void *p;
  if ((p = malloc(size)) == NULL)
  {
    default_oom_handler(size);
    fprintf(stderr, "Fatal: Return from out-of-memory handler.\n");
    abort();
  }
  memset(p, 0, size);
  return p;
}

void *xrealloc(void *p, size_t size)
{
  if ((p = realloc(p, size)) == NULL)
  {
    default_oom_handler(size);
    fprintf(stderr, "Fatal: Return from out-of-memory handler.\n");
    abort();
  }

  return p;
}

void xfree(void *p)
{
  free(p);
}
