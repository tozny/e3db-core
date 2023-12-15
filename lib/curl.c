/*
 * curl.c
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
#include <curl/curl.h>
#include "e3db_mem.h"
#include "e3db_core.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "http_parser.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int MAX_BUFFER_SIZE = 8192;
int MAX_REQUEST_SIZE = 10000;
int MAX_HEADER_SIZE = 8192;
// Define a structure to hold the response data
struct ResponseData
{
	char *data;
	size_t size;
	long response_code;
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

// HTTP parser callback for handling body data
int http_parser_body_callback(http_parser *parser, const char *at, size_t length)
{
	struct ResponseData *response_data = (struct ResponseData *)parser->data;

	response_data->data = realloc(response_data->data, response_data->size + length + 1);
	if (response_data->data == NULL)
	{
		fprintf(stderr, "http_parser_body_callback: realloc failed\n");
		return 1; // Returning non-zero indicates an error to the HTTP parser
	}

	memcpy(&(response_data->data[response_data->size]), at, length);
	response_data->size += length;
	response_data->data[response_data->size] = 0; // Null-terminate the data

	return 0;
}

int http_parser_status_callback(http_parser *parser, const char *at, size_t length)
{
	// Access the status code directly from the parser
	struct ResponseData *response_data = (struct ResponseData *)parser->data;

	// Convert the status code string to a long
	response_data->response_code = parser->status_code;

	// Print debug information
	printf("Status Callback: at='%.*s', length=%zu\n", (int)length, at, length);
	printf("Status Code: %d\n", parser->status_code);
	printf("Response Code: %ld\n", response_data->response_code);

	return 0;
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
int on_headers_complete(http_parser *parser)
{
	// You can handle additional logic if needed
	return 0;
}
// Define http_parser_settings
http_parser_settings parser_settings = {
    .on_body = http_parser_body_callback,
    .on_status = http_parser_status_callback,
    .on_headers_complete = on_headers_complete, // add this line
};

int curl_run_op(E3DB_Op *op)
{
	CURL *curl;
	struct ResponseData response_data = {NULL, 0};

	if ((curl = curl_easy_init()) == NULL)
	{
		fprintf(stderr, "Fatal: Curl initialization failed.\n");
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
				// free(header_text);

				header = E3DB_HttpHeader_GetNext(header);
			}
			printf("Header in curl  %s \n", chunk->data);
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
	curl_easy_cleanup(curl);
	return 0;
}

int curl_run_op_with_expected_response_code(E3DB_Op *op, long expected_response_code)
{
	CURL *curl;
	struct ResponseData response_data = {NULL, 0};

	if ((curl = curl_easy_init()) == NULL)
	{
		fprintf(stderr, "Fatal: Curl initialization failed.\n");
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
				curl_easy_cleanup(curl);
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

	curl_easy_cleanup(curl);
	return 0;
}

int mbedtls_run_op(E3DB_Op *op)
{
	// Set up objects
	mbedtls_net_context server_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *hostname = "api.e3db.com";
	const char *port = "443";
	int ret;

	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);

	if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
	{
		fprintf(stderr, "Failed to set up SSL configuration.\n");
		exit(EXIT_FAILURE);
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	struct ResponseData response_data = {NULL, 0};

	http_parser parser;
	http_parser_init(&parser, HTTP_RESPONSE);

	parser.data = &response_data;

	// Set hostname for Server Name Indication (SNI)
	ret = mbedtls_ssl_set_hostname(&ssl, hostname);
	if (ret != 0)
	{
		fprintf(stderr, "Failed to set hostname. %d\n", ret);
		exit(EXIT_FAILURE);
	}

	// Initialize entropy source
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	// Initialize random seed source
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0)
	{
		fprintf(stderr, "Failed to set drbg seed. %d\n", ret);
		exit(EXIT_FAILURE);
	}

	// Set SSL context random seed source
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	/* Assign the TLS config to the TLS context. */
	if (mbedtls_ssl_setup(&ssl, &conf) != 0)
	{
		fprintf(stderr, "Failed to setup ssl. %d\n", ret);
		exit(EXIT_FAILURE);
	}

	// Connect to the server
	if (mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_SSL_TRANSPORT_STREAM) != 0)
	{
		fprintf(stderr, "Failed to connect to server.\n");
		exit(EXIT_FAILURE);
	}

	// Handshake with server
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			fprintf(stderr, "Failed to make ssl handshake. %d\n", ret);
			exit(EXIT_FAILURE);
		}
	}

	while (!E3DB_Op_IsDone(op))
	{
		if (E3DB_Op_IsHttpState(op))
		{
			const char *method = E3DB_Op_GetHttpMethod(op);

			printf("METHOD being processed %s\n", method);

			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
			size_t lengthOfhEders = E3DB_HttpHeaderList_GetLength(headers);
			printf("HEADERS LENGTH %zu", lengthOfhEders);
			E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

			// Allocate memory for headers_string and request
			char *headers_string = (char *)xmalloc(MAX_HEADER_SIZE);
			headers_string[0] = '\0'; // Initialize the string to an empty string
			char *request = (char *)xmalloc(MAX_REQUEST_SIZE);

			// Check for allocation errors
			if (headers_string == NULL || request == NULL)
			{
				fprintf(stderr, "Memory allocation error.\n");
				exit(EXIT_FAILURE);
			}
			while (header != NULL)
			{
				char *header_text = (char *)xmalloc(strlen(E3DB_HttpHeader_GetName(header)) + strlen(E3DB_HttpHeader_GetValue(header)) + 3);
				if (header_text == NULL)
				{
					fprintf(stderr, "Memory allocation error.\n");
					exit(EXIT_FAILURE);
				}
				sprintf(header_text, "%s: %s\r\n", E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
				strcat(headers_string, header_text);
				// free(header_text); // Free the allocated memory
				header = E3DB_HttpHeader_GetNext(header);
			}

			if (!strcmp(method, "POST"))
			{
				const char *post_body = E3DB_Op_GetHttpBody(op);
				printf("URL length: %zu\n", strlen(E3DB_Op_GetHttpUrl(op)));
				printf("Headers length: %zu\n", strlen(headers_string));
				printf("Post body length: %zu\n", strlen(post_body));
				int ret = snprintf(request, MAX_REQUEST_SIZE,
						   "POST %s HTTP/1.1\r\n"
						   "Host: api.e3db.com\r\n" // Use only the hostname
						   "Content-Length: %zu\r\n"
						   "%s\r\n" // Authorization header
						   "%s",    // Request body
						   E3DB_Op_GetHttpUrl(op), strlen(post_body), headers_string, post_body);

				printf("Ret size %d", ret);
				printf("snprintf returned: %d\n", ret);
				if (ret < 0 || ret >= MAX_REQUEST_SIZE - 1) // -1 to leave room for the null terminator
				{
					fprintf(stderr, "Error constructing request.\n");
					exit(EXIT_FAILURE);
				}
				printf("Request %s\n", request);
				printf("URL: %s\n", E3DB_Op_GetHttpUrl(op));
				printf("Headers: %s\n", headers_string);
				printf("Post Body: %s\n", post_body);
			}
			else if (!strcmp(method, "GET"))
			{
				printf("URL length: %zu\n", strlen(E3DB_Op_GetHttpUrl(op)));
				printf("URL length: %s\n", E3DB_Op_GetHttpUrl(op));
				printf("Headers length: %zu\n", strlen(headers_string));
				int ret = snprintf(request, MAX_REQUEST_SIZE,
						   "GET %s HTTP/1.1\r\n"
						   "Host: api.e3db.com\r\n" // Use only the hostname
						   "%s\r\n"		    // Additional headers if needed
						   "\r\n",		    // No request body for GET
						   E3DB_Op_GetHttpUrl(op), headers_string);
				if (ret < 0 || ret >= MAX_REQUEST_SIZE - 1) // -1 to leave room for the null terminator
				{
					fprintf(stderr, "Error constructing request.\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (!strcmp(method, "PUT"))
			{
				const char *put_body = E3DB_Op_GetHttpBody(op);
				printf("Put Body: %s\n", put_body);
				printf("Len Put Body: %d\n", strlen(put_body));

				snprintf(request, MAX_REQUEST_SIZE,
					 "PUT %s HTTP/1.1\r\n"
					 "Host: api.e3db.com\r\n"
					 "Content-Length: %zu\r\n"
					 "%s\r\n" // Additional headers, like Authorization
					 "%s",	  // JSON body
					 E3DB_Op_GetHttpUrl(op), strlen(put_body), headers_string, put_body);

				if (ret < 0 || ret >= MAX_REQUEST_SIZE - 1) // -1 to leave room for the null terminator
				{
					fprintf(stderr, "Error constructing request.\n");
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				fprintf(stderr, "Unsupported method: %s\n", method);
				abort();
			}
			printf("Request: %s\n", request);
			if (mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request)) != strlen(request))
			{
				fprintf(stderr, "Failed to set up HTTP Request.\n");
				exit(EXIT_FAILURE);
			}

			// Allocate memory for the response buffer
			char *buffer = (char *)xmalloc(MAX_BUFFER_SIZE);
			// Check for allocation errors
			if (buffer == NULL)
			{
				fprintf(stderr, "Memory allocation error.\n");
				exit(EXIT_FAILURE);
			}

			int bytes_received = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, MAX_BUFFER_SIZE);
			printf("Bytes received %d\n", bytes_received);
			if (bytes_received < 0)
			{
				// Handle mbedtls_ssl_read error
				fprintf(stderr, "mbedtls_ssl_read error: %d\n", bytes_received);
				break; // Exit the loop on error
			}
			// Handle buffer overflow, reallocate if necessary
			if (bytes_received > MAX_BUFFER_SIZE)
			{
				char *new_buffer = (char *)xrealloc(buffer, MAX_BUFFER_SIZE + bytes_received);
				if (new_buffer == NULL)
				{
					// Handle reallocation failure
					free(buffer);
					fprintf(stderr, "Memory reallocation error.\n");
					exit(EXIT_FAILURE);
				}
				buffer = new_buffer;
			}
			printf("Bytes received %d\n", bytes_received);
			printf("\n Buffer: %s \n", buffer);
			printf("%s", "End of buffer");
			if (http_parser_execute(&parser, &parser_settings, buffer, bytes_received) != bytes_received)
			{
				fprintf(stderr, "HTTP parsing error.\n");
				mbedtls_ssl_close_notify(&ssl);
				mbedtls_net_free(&server_fd);
				mbedtls_x509_crt_free(&cacert);
				mbedtls_ssl_free(&ssl);
				mbedtls_ssl_config_free(&conf);
				exit(EXIT_FAILURE);
			}

			printf("Buffer: %.*s\n", bytes_received, buffer);
			printf("Response data: %s\n", response_data.data);
			printf("Response data: %ld\n", response_data.response_code);
			// Pass the response data to E3DB_Op_FinishHttpState
			E3DB_Op_FinishHttpState(op, response_data.response_code, response_data.data, NULL, 0);
			// Free memory at the end
			free(headers_string);
			free(request);
			free(buffer);
		}
	}

	// Clean up mbedtls components
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);

	// Free memory for response data
	free_response_data(&response_data);
	printf("%s", "Done!");

	return 0;
}
