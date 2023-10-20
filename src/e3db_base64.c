/*
 * e3db_base64.c --- Base64 encoding and decoding.
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "sds.h"
#include "cdecode.h"
#include "cdecode.h"

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

	BIO_flush(bio);
	long len = BIO_get_mem_data(bio, &buf);
	char *null_terminated_buffer = (char *)malloc(len + 1); // one extra byte for null terminator
	memcpy(null_terminated_buffer, buf, len);
	null_terminated_buffer[len] = '\0'; // ensure null-termination
	
	result = sdsnew(null_terminated_buffer);

	BIO_free_all(bio);
	free(null_terminated_buffer);

	return result;
}

sds sdsRemoveBytes(sds str, size_t start, size_t count)
{
	if (str == NULL)
		return NULL;
	size_t len = sdslen(str);
	if (start >= len)
		return str; // Nothing to remove

	// Calculate the new length of the string
	size_t new_len = len - count;
	if (new_len >= len)
		return str; // Avoid underflow

	// Remove the specified bytes by shifting the data
	memmove(str + start, str + start + count, len - start - count + 1); // +1 for null terminator

	// Update the length of the string
	sdssetlen(str, new_len);

	return str;
}

sds base64_encodeUrl(const char *s)
{
	BIO *bio, *b64;
	char *buf;
	sds result;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, s, strlen(s));
	// BIO_write(bio, "\0", 1);
	BIO_flush(bio);


	long len = BIO_get_mem_data(bio, &buf);
	char *null_terminated_buffer = (char *)malloc(len + 1); // one extra byte for null terminator
	memcpy(null_terminated_buffer, buf, len);
	null_terminated_buffer[len] = '\0'; // ensure null-termination

	result = sdsnew(null_terminated_buffer);

	BIO_free_all(bio);
	free(null_terminated_buffer);

	for (int i = 0; i < strlen(result); i++)
	{
		if (result[i] == '/')
		{
			result[i] = '_';
		}
		else if (result[i] == '+')
		{
			result[i] = '-';
		}
	}
	// Remove padding characters '='
	int padding = 0;
	for (int i = strlen(result) - 1; i >= 0; i--)
	{
		if (result[i] == '=')
		{
			padding++;
		}
		else
		{
			break;
		}
	}
	result[strlen(result) - padding] = '\0';
	return result;
}

sds base64_encodeUrl2(const char *s, size_t size)
{
	BIO *bio, *b64;
	char *buf;
	sds result;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, s, size);
	// BIO_write(bio, "\0", 1);
	BIO_flush(bio);

	long len = BIO_get_mem_data(bio, &buf);
	char *null_terminated_buffer = (char *)malloc(len + 1); // one extra byte for null terminator
	memcpy(null_terminated_buffer, buf, len);
	null_terminated_buffer[len] = '\0'; // ensure null-termination

	result = sdsnew(null_terminated_buffer);

	BIO_free_all(bio);
	free(null_terminated_buffer);

	for (int i = 0; i < size; i++)
	{
		if (result[i] == '/')
		{
			result[i] = '_';
		}
		else if (result[i] == '+')
		{
			result[i] = '-';
		}
	}

	return result;
}

unsigned char *base64_decode(const char *base64)
{
	unsigned char *input;
	input = (unsigned char *)malloc(strlen(base64) * sizeof(char) + 1);
	// Remove double quotes, replace url encoded chars _ with / and - with +.
	int count = 0;
	int quotes = 0;
	for (int i = 0; i < strlen(base64); i++)
	{
		if (base64[i] == '_')
		{
			input[count] = '/';
			count++;
		}
		else if (base64[i] == '-')
		{
			input[count] = '+';
			count++;
		}
		else if (base64[i] != '"')
		{
			input[count] = base64[i];
			count++;
		}
		else
		{
			quotes++;
		}
	}
	input = (unsigned char *)realloc(input, (strlen(base64) - quotes) * sizeof(unsigned char) + 1);
	input[count] = '\0';
	/* set up a destination buffer large enough to hold the encoded data */
	unsigned char *output = (unsigned char *)malloc(strlen((char *)input) + 1);
	/* keep track of our decoded position */
	unsigned char *c = output;
	/* store the number of bytes decoded by a single call */
	int cnt = 0;
	/* we need a decoder state */
	base64_decodestate s;

	/*---------- START DECODING ----------*/
	/* initialise the decoder state */
	base64_init_decodestate(&s);
	/* decode the input data */
	cnt = base64_decode_block((char *)input, strlen((char *)input), (char *)c, &s);
	c += cnt;
	/* note: there is no base64_decode_blockend! */
	/*---------- STOP DECODING  ----------*/

	/* we want to print the decoded data, so null-terminate it: */
	*c = 0;
	output[strlen((char *)input)] = '\0';
	free(input);
	return output;
}

unsigned char *base64_decode2(const char *base64, int *cnt)
{
	unsigned char *input;
	input = (unsigned char *)malloc(strlen(base64) * sizeof(char) + 1);
	// Remove double quotes, replace url encoded chars _ with / and - with +.
	int count = 0;
	int quotes = 0;
	for (int i = 0; i < strlen(base64); i++)
	{
		if (base64[i] == '_')
		{
			input[count] = '/';
			count++;
		}
		else if (base64[i] == '-')
		{
			input[count] = '+';
			count++;
		}
		else if (base64[i] != '"')
		{
			input[count] = base64[i];
			count++;
		}
		else
		{
			quotes++;
		}
	}
	input = (unsigned char *)realloc(input, (strlen(base64) - quotes) * sizeof(unsigned char) + 1);
	input[count] = '\0';
	/* set up a destination buffer large enough to hold the encoded data */
	unsigned char *output = (unsigned char *)malloc(strlen((char *)input) + 1);
	/* keep track of our decoded position */
	/* store the number of bytes decoded by a single call */
	*cnt = 0;
	/* we need a decoder state */
	base64_decodestate s;

	/*---------- START DECODING ----------*/
	/* initialise the decoder state */
	base64_init_decodestate(&s);
	/* decode the input data */
	*cnt = base64_decode_block((char *)input, strlen((char *)input), (char *)output, &s);
	/* note: there is no base64_decode_blockend! */
	/*---------- STOP DECODING  ----------*/

	/* we want to print the decoded data, so null-terminate it: */
	// output[strlen((char *)input)] = '\0';
	// output = (unsigned char *)realloc(output, cnt + 1);

	free(input);
	return output;
}
