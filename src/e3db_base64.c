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
#include "lib/b64/cdecode.h"

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

sds base64_decode(const char* base64)
{
	char *input;
	input = (char *)malloc(strlen(base64) * sizeof(char) + 1);
	// Remove double quotes, replace url encoded chars _ with / and - with +.
	int count = 0;
	int quotes = 0;
	for(int i=0; i<strlen(base64); i++) {
		if (base64[i] == '_'){
			input[count] = '/';
			count ++;
		} else if (base64[i] == '-'){
			input[count] = '+';
			count ++;
		} else if (base64[i] != '"') {
			input[count] = base64[i];
			count ++;
		} else {
			quotes++;
		}
		input = (char *)realloc(input, (strlen(base64) - quotes)*sizeof(char)+1);
	}
	printf("\n Input to base64 decode: %s - %d", base64, strlen(input));
	BIO *bio, *b64;
	int decodeLen = strlen(input);
	unsigned char *buffer = (unsigned char *)malloc(decodeLen + 1); // +1 for the null terminator
	if (buffer == NULL)
	{
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}

	memset(buffer, 0, decodeLen + 1); // Initialize buffer to zeros

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_mem_buf(input, -1); // -1 indicates string is null terminated
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Don't require newlines

	int bytesRead = BIO_read(bio, buffer, decodeLen);
	if (bytesRead < 0)
	{
		fprintf(stderr, "BIO_read failed\n");
		free(buffer);
		BIO_free_all(bio);
		return NULL;
	}

	buffer[bytesRead] = '\0'; // Null-terminate the result

	printf("\n");
	for(int i=0; i<strlen(buffer); i++) {
		printf("%d ", buffer[i]);
	}
	printf("\n Buffered length: %d", strlen(buffer));
	return buffer;
}
