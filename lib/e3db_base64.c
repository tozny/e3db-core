/*
 * e3db_base64.c --- Base64 encoding and decoding.
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#include <string.h>

#include "cdecode.h"
#include "cencode.h"
#include "e3db_mem.h"
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls_base64.h"

char *encode64_length(const char *input, size_t length)
{
	/* set up a destination buffer large enough to hold the encoded data */
	size_t output_len = ((length + 2) / 3) * 4 + 1; // +1 for null-terminator
	char *output = (char *)xmalloc(output_len);
	if (output == NULL)
	{
		printf("Failed to allocate memory\n");
		abort();
	}
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
	*c = 0; // Null-terminate
	/*---------- STOP ENCODING  ----------*/

	// Replace '/' with '_' and '+' with '-' for URL safety
	for (char *p = output; *p; p++)
	{
		if (*p == '/')
			*p = '_';
		else if (*p == '+')
			*p = '-';
	}

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
	unsigned char *input = (unsigned char *)malloc(len + 1);
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

	unsigned char *buffer = (unsigned char *)malloc(decoded_length + 1); // +1 for null terminator
	if (!buffer)
	{
		fprintf(stderr, "Error: Failed to allocate memory for 'output'.\n");
		free(input);
		return NULL;
	}

	// Use mbedtls base64 decoding
	size_t out_len;
	int ret = mbedtls_base64_decode(buffer, decoded_length, &out_len, input, count);
	if (ret != 0)
	{
		fprintf(stderr, "mbedtls_base64_decode failed: %d\n", ret);
		free(buffer);
		free(input);
		return NULL;
	}

	buffer[out_len] = '\0'; // Null-terminate the result
	*cnt = out_len;
	free(input);
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
