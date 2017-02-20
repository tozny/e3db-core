/*
 * mem.h --- Memory management utilities.
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#ifndef E3DB_MEM_H_INCLUDED
#define E3DB_MEM_H_INCLUDED

void *xmalloc(size_t size);
void *xrealloc(void *p, size_t size);
void xfree(void *p);

#endif   /* !defined E3DB_MEM_H_INCLUDED */
