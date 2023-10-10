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
	BIO_write(bio, "\0", 1);
	BIO_flush(bio);

	BIO_get_mem_data(bio, &buf);
	result = sdsnew(buf);

	BIO_free_all(bio);
	return result;
}

sds base64_decode(const char *base64)
{
	char *input;
	input = (char *)malloc(strlen(base64) * sizeof(char) + 1);
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
	input = (char *)realloc(input, (strlen(base64) - quotes) * sizeof(char) + 1);
	input[count] = '\0';
	printf("URL Decoded Count: %d \n", count);
	printf("URL Decoded base64: %s \n", input);
	/* set up a destination buffer large enough to hold the encoded data */
	unsigned char *output = (char *)malloc(strlen(input) + 1);
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
	cnt = base64_decode_block(input, strlen(input), c, &s);
	c += cnt;
	/* note: there is no base64_decode_blockend! */
	/*---------- STOP DECODING  ----------*/

	/* we want to print the decoded data, so null-terminate it: */
	*c = 0;
	free(input);
	output[strlen(input) - 1] = '\0';
	printf("\n");
	for (int i = 0; i < strlen(output); i++)
	{
		printf("%d ", output[i]);
	}
	printf("\n Buffered length: %d", strlen(output));
	return output;
}
