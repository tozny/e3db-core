/*
 * e3db_base64.c --- Base64 encoding and decoding.
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#include <string.h>
#include <sodium.h>

#include "sds.h"

sds base64_encode(const char *s)
{
  size_t len = strlen(s);
  char buf[sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)];

  sodium_bin2base64(buf, sizeof(buf), (void *)s, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  return sdsnew(buf);
}

