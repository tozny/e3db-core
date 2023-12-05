/*
 * e3db_base64.h --- Base64 encoding and decoding.
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#ifndef E3DB_BASE64_H_INCLUDED
#define E3DB_BASE64_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include "sds.h"

	char *encode64_length(const char *s, size_t length);
	unsigned char *base64_decode(const char *s);
	unsigned char *base64_decode_with_count(const char *s, int *count);
	unsigned char *base64_decode_with_count_simple(const char *s, int *count);

#ifdef __cplusplus
}
#endif

#endif /* !defined E3DB_BASE64_H_INCLUDED */
