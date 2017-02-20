/*
 * e3db_base64.c --- Base64 encoding and decoding.
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "sds.h"

sds base64_encode(const char *s)
{
  BIO *bio, *b64;
  char *buf;
  sds result;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, s, strlen(s));
  BIO_write(bio, "\0", 1);
  BIO_flush(bio);

  BIO_get_mem_data(bio, &buf);
  result = sdsnew(buf);

  BIO_free_all(bio);
  return result;
}
