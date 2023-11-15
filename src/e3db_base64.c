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
#include "cencode.h"
#include "e3db_mem.h"

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
	char *null_terminated_buffer = (char *)xmalloc(len + 1); // one extra byte for null terminator
	memcpy(null_terminated_buffer, buf, len);

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
	BIO_flush(bio);

	long len = BIO_get_mem_data(bio, &buf);
	char *null_terminated_buffer = (char *)xmalloc(len + 1); // one extra byte for null terminator
	memcpy(null_terminated_buffer, buf, len);

	result = sdsnew(null_terminated_buffer);

	BIO_free_all(bio);
	free(null_terminated_buffer);

	int result_len = sdslen(result);
	for (int i = 0; i < result_len; i++)
	{
		switch (result[i])
		{
		case '/':
			result[i] = '_';
			break;
		case '+':
			result[i] = '-';
			break;
		}
	}
	result[result_len] = '\0';
	return result;
}

char *encode64_length(const char *input, size_t length)
{
	// printf("start encoding %s \n ", input);
	/* set up a destination buffer large enough to hold the encoded data */
	char *output = (char *)xmalloc(200);
	/* keep track of our encoded position */
	char *c = output;
	/* store the number of bytes encoded by a single call */
	int cnt = 0;
	/* we need an encoder state */
	base64_encodestate s;

	/*---------- START ENCODING ----------*/
	/* initialise the encoder state */
	base64_init_encodestate(&s);
	/* gather data from the input and send it to the output */
	cnt = base64_encode_block(input, length, c, &s);
	c += cnt;
	/* since we have encoded the entire input string, we know that
	   there is no more input data; finalise the encoding */
	cnt = base64_encode_blockend(c, &s);
	c += cnt;
	/*---------- STOP ENCODING  ----------*/

	/* we want to print the encoded data, so null-terminate it: */
	*c = 0;
	printf(" end encoding%s \n", output);

	int result_len = strlen(output);
	for (int i = 0; i < result_len; i++)
	{
		switch (output[i])
		{
		case '/':
			output[i] = '_';
			break;
		case '+':
			output[i] = '-';
			break;
		}
	}
	output[result_len] = '\0';
	return output;
}

unsigned char *base64_decode(const char *base64)
{
	int len = strlen(base64);
	int padding = 0;
	unsigned char *processed_input = (unsigned char *)xmalloc(len + 1);
	if (!processed_input)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'input'.\n");
		return NULL;
	}
	// Remove double quotes, replace url encoded chars _ with / and - with +.
	int count = 0;
	for (int i = 0; i < len; i++)
	{
		switch (base64[i])
		{
		case '_':
			processed_input[count++] = '/';
			break;
		case '-':
			processed_input[count++] = '+';
			break;
		case '"':
			break;
		default:
			processed_input[count++] = base64[i];
		}
	}
	// Count the padding characters in the processed input
	for (int i = count - 1; i >= 0 && processed_input[i] == '='; i--)
	{
		padding++;
	}

	// Calculate the maximum decoded length
	int decoded_length = (count * 3) / 4 - padding;

	/* set up a destination buffer large enough to hold the encoded data */
	unsigned char *output = (unsigned char *)xmalloc(decoded_length + 1); // +1 for null terminator
	if (!output)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'output'.\n");
		free(processed_input);
		return NULL;
	}

	// /* keep track of our decoded position */
	// unsigned char *c = output;

	/* we need a decoder state */
	base64_decodestate state;

	/*---------- START DECODING ----------*/
	/* initialise the decoder state */
	base64_init_decodestate(&state);
	/* decode the input data */
	int actual_decoded_length = base64_decode_block((char *)processed_input, count, (char *)output, &state);
	/* note: there is no base64_decode_blockend! */

	/* Null-terminate the output */
	output[actual_decoded_length] = '\0';
	/*---------- STOP DECODING  ----------*/

	free(processed_input);
	return output;
}

unsigned char *base64_decode_with_count_simple(const char *base64, int *cnt)
{
	int len = strlen(base64);
	int padding = 0;
	// Process the base64 string: remove double quotes, replace URL encoded characters
	unsigned char *input = (unsigned char *)xmalloc(len + 1);
	if (!input)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'processed_input'.\n");
		return NULL;
	}

	// Remove double quotes, replace url encoded chars _ with / and - with +.
	int count = 0;
	for (int i = 0; i < len; i++)
	{
		switch (base64[i])
		{
		case '_':
			input[count++] = '/';
			break;
		case '-':
			input[count++] = '+';
			break;
		case '"':
			break;
		default:
			input[count++] = base64[i];
		}
	}
	// Count the padding characters in the processed input
	for (int i = count - 1; i >= 0 && input[i] == '='; i--)
	{
		padding++;
	}

	// Calculate the maximum decoded length
	int decoded_length = (count * 3) / 4 - padding;

	BIO *bio, *b64;

	unsigned char *buffer = (unsigned char *)xmalloc(decoded_length + 1); // +1 for null terminator
	if (!buffer)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'output'.\n");
		free(input);
		return NULL;
	}

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_mem_buf(input, -1); // -1 indicates string is null terminated
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Don't require newlines

	int bytesRead = BIO_read(bio, buffer, decoded_length);
	if (bytesRead < 0)
	{
		fprintf(stderr, "BIO_read failed\n");
		free(buffer);
		BIO_free_all(bio);
		return NULL;
	}

	buffer[bytesRead] = '\0'; // Null-terminate the result
	*cnt = bytesRead;
	return buffer;
}

unsigned char *base64_decode_with_count(const char *base64, int *cnt)
{
	int len = strlen(base64);
	unsigned char *input = (unsigned char *)xmalloc(len + 1);
	if (!input)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'input'.\n");
		return NULL;
	}

	// Remove double quotes, replace url encoded chars _ with / and - with +.
	int count = 0;
	for (int i = 0; i < len; i++)
	{
		switch (base64[i])
		{
		case '_':
			input[count++] = '/';
			break;
		case '-':
			input[count++] = '+';
			break;
		case '"':
			break;
		default:
			input[count++] = base64[i];
		}
	}

	unsigned char *new_input = xrealloc(input, count + 1);
	if (!new_input)
	{
		fprintf(stderr, "Error: Failed to reallocate memory for 'input'.\n");
		free(input);
		return NULL;
	}
	input = new_input;

	/* set up a destination buffer large enough to hold the encoded data */
	unsigned char *output = (unsigned char *)xmalloc(count + 1);
	if (!output)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'output'.\n");
		free(input);
		return NULL;
	}

	/* keep track of our decoded position */
	/* store the number of bytes decoded by a single call */
	*cnt = 0;
	/* we need a decoder state */
	base64_decodestate s;

	/*---------- START DECODING ----------*/
	/* initialise the decoder state */
	base64_init_decodestate(&s);
	/* decode the input data */
	*cnt = base64_decode_block((char *)input, count, (char *)output, &s);
	/* note: there is no base64_decode_blockend! */
	/*---------- STOP DECODING  ----------*/

	free(input);
	return output;
}
