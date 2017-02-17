/*
 * mem.c --- Memory management utilities.
 *
 * Copyright (C) 2017, Tozny, LLC.
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
  if ((p = malloc(size)) == NULL) {
    default_oom_handler(size);
    fprintf(stderr, "Fatal: Return from out-of-memory handler.\n");
    abort();
  }
  memset(p, 0, size);
  return p;
}

void xfree(void *p)
{
  free(p);
}

char *xstrdup(const char *str)
{
  size_t len = strlen(str) + 1;
  char *p = xmalloc(len);
  memcpy(p, str, len);
  return p;
}
