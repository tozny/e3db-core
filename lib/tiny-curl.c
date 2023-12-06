/*
 * tiny_curl.c
 *
 *
 * Copyright (C) 2017-2023, Tozny, LLC.
 * All Rights Reserved.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sds.h"
#include <tiny-curl/curl.h>
#include "e3db_core.h"

// Define a structure to hold the response data
struct ResponseData
{
	char *data;
	size_t size;
};

// Function to free the response data
void free_response_data(struct ResponseData *response_data)
{
	if (response_data->data != NULL)
	{
		free(response_data->data);
		response_data->data = NULL;
		response_data->size = 0;
	}
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct ResponseData *mem = (struct ResponseData *)userp;

	mem->data = realloc(mem->data, mem->size + realsize + 1);
	if (mem->data == NULL)
	{
		fprintf(stderr, "write_callback: realloc failed\n");
		return 0; // Returning 0 indicates an error to libcurl
	}

	memcpy(&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0; // Null-terminate the data

	return realsize;
}
int curl_run_op(E3DB_Op *op)
{
	TinyCURL *curl;
	struct ResponseData response_data = {NULL, 0};

	// Initialize tiny-curl
	if (tiny_curl_global_init() != TINYCURL_OK)
	{
		fprintf(stderr, "Fatal: Tiny-curl initialization failed.\n");
		exit(EXIT_FAILURE);
	}

	// Create a tiny-curl handle
	if ((curl = tiny_curl_easy_init()) == NULL)
	{
		fprintf(stderr, "Fatal: Tiny-curl easy initialization failed.\n");
		exit(EXIT_FAILURE);
	}

	while (!E3DB_Op_IsDone(op))
	{
		if (E3DB_Op_IsHttpState(op))
		{
			curl_easy_reset(curl);

			const char *method = E3DB_Op_GetHttpMethod(op);
			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);

			struct curl_slist *chunk = NULL;
			E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

			while (header != NULL)
			{
				char *header_text = malloc(strlen(E3DB_HttpHeader_GetName(header)) + strlen(E3DB_HttpHeader_GetValue(header)) + 3);
				sprintf(header_text, "%s: %s", E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
				chunk = curl_slist_append(chunk, header_text);
				free(header_text);

				header = E3DB_HttpHeader_GetNext(header);
			}

			if (!strcmp(method, "POST"))
			{
				const char *post_body = E3DB_Op_GetHttpBody(op);
				curl_easy_setopt(curl, CURLOPT_POST, 1L);
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
			}
			else if (!strcmp(method, "GET"))
			{
				// nothing special for GET
			}
			else if (!strcmp(method, "PUT"))
			{
				const char *put_body = E3DB_Op_GetHttpBody(op);
				curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, put_body);
			}
			else
			{
				fprintf(stderr, "Unsupported method: %s\n", method);
				abort();
			}
			curl_easy_setopt(curl, CURLOPT_URL, E3DB_Op_GetHttpUrl(op));
			// Turn on for debugging
			// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

			CURLcode res = curl_easy_perform(curl);
			if (res != CURLE_OK)
			{
				fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
			}

			long response_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

			// Pass the response data to E3DB_Op_FinishHttpState
			E3DB_Op_FinishHttpState(op, response_code, response_data.data, NULL, 0);
			// Free allocated memory
			curl_slist_free_all(chunk);
			free_response_data(&response_data);
		}
	}
	// Free memory for response data
	tiny_curl_easy_cleanup(curl);
	tiny_curl_global_cleanup();
	return 0;
}

int curl_run_op_with_expected_response_code(E3DB_Op *op, long expected_response_code)
{
	TinyCURL *curl;
	struct ResponseData response_data = {NULL, 0};

	// Initialize tiny-curl
	if (tiny_curl_global_init() != TINYCURL_OK)
	{
		fprintf(stderr, "Fatal: Tiny-curl initialization failed.\n");
		exit(EXIT_FAILURE);
	}

	// Create a tiny-curl handle
	if ((curl = tiny_curl_easy_init()) == NULL)
	{
		fprintf(stderr, "Fatal: Tiny-curl easy initialization failed.\n");
		exit(EXIT_FAILURE);
	}

	while (!E3DB_Op_IsDone(op))
	{
		if (E3DB_Op_IsHttpState(op))
		{
			curl_easy_reset(curl);

			const char *method = E3DB_Op_GetHttpMethod(op);
			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);

			struct curl_slist *chunk = NULL;
			E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

			while (header != NULL)
			{
				char *header_text = malloc(strlen(E3DB_HttpHeader_GetName(header)) + strlen(E3DB_HttpHeader_GetValue(header)) + 3);
				sprintf(header_text, "%s: %s", E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
				chunk = curl_slist_append(chunk, header_text);
				free(header_text);

				header = E3DB_HttpHeader_GetNext(header);
			}

			if (!strcmp(method, "POST"))
			{
				const char *post_body = E3DB_Op_GetHttpBody(op);
				curl_easy_setopt(curl, CURLOPT_POST, 1L);
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
			}
			else if (!strcmp(method, "GET"))
			{
				// nothing special for GET
			}
			else
			{
				fprintf(stderr, "Unsupported method: %s\n", method);
				abort();
			}

			curl_easy_setopt(curl, CURLOPT_URL, E3DB_Op_GetHttpUrl(op));
			// Turn on for debugging
			// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

			CURLcode res = curl_easy_perform(curl);
			if (res != CURLE_OK)
			{
				fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
			}

			long response_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
			if (response_code == expected_response_code)
			{
				// Cleanup tiny-curl
				tiny_curl_easy_cleanup(curl);
				tiny_curl_global_cleanup();
				curl_slist_free_all(chunk);
				free_response_data(&response_data);
				return expected_response_code;
			}

			// Pass the response data to E3DB_Op_FinishHttpState
			E3DB_Op_FinishHttpState(op, response_code, response_data.data, NULL, 0);
			// Free allocated memory
			free_response_data(&response_data);
			curl_slist_free_all(chunk);
		}
	}

	// Cleanup tiny-curl
	tiny_curl_easy_cleanup(curl);
	tiny_curl_global_cleanup();

	return 0;
}
