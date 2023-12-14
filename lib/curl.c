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
#include "e3db_core.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "http_parser.h"

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

// HTTP parser callback for handling status code
int http_parser_status_callback(http_parser *parser, const char *at, size_t length)
{
	struct ResponseData *response_data = (struct ResponseData *)parser->data;

	// Convert the status code string to a long
	response_data->response_code = strtol(at, NULL, 10);

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

// Define http_parser_settings
http_parser_settings parser_settings = {
    .on_body = http_parser_body_callback,
    .on_status = http_parser_status_callback,
    // Add other callbacks as needed
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

	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);

	if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
	{
		fprintf(stderr, "Failed to set up SSL configuration.\n");
		exit(EXIT_FAILURE);
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	struct ResponseData response_data = {NULL, 0};

	http_parser parser;
	http_parser_init(&parser, HTTP_RESPONSE);

	parser.data = &response_data;

	while (!E3DB_Op_IsDone(op))
	{
		if (E3DB_Op_IsHttpState(op))
		{
			const char *method = E3DB_Op_GetHttpMethod(op);
			printf("METHOD being processed %s\n", method);

			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);

			E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

			char headers_string[4096]; // Adjust the size based on your needs
			headers_string[0] = '\0';  // Initialize the string to an empty string

			while (header != NULL)
			{
				char *header_text = malloc(strlen(E3DB_HttpHeader_GetName(header)) + strlen(E3DB_HttpHeader_GetValue(header)) + 3);
				sprintf(header_text, "%s: %s", E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
				strcat(headers_string, header_text);
				free(header_text);

				header = E3DB_HttpHeader_GetNext(header);
			}

			printf("All headers as a string: %s\n", headers_string);
			char request[8192]; // Adjust the size based on your needs
			request[0] = '\0';  // Initialize the string to an empty string

			if (!strcmp(method, "POST"))
			{
				const char *post_body = E3DB_Op_GetHttpBody(op);

				snprintf(request, sizeof(request),
					 "POST %s HTTP/1.1\r\n"
					 "Host: %s\r\n"
					 "Content-Length: %d\r\n"
					 "%s\r\n"  // Authorization header
					 "\r\n%s", // Request body
					 E3DB_Op_GetHttpUrl(op), E3DB_Op_GetHttpUrl(op), strlen(post_body), headers_string, post_body);
				printf("Request %s\n", request);
			}
			else if (!strcmp(method, "GET"))
			{
				snprintf(request, sizeof(request),
					 "GET %s HTTP/1.1\r\n"
					 "Host: %s\r\n"
					 "%s\r\n" // Additional headers if needed
					 "\r\n",  // No request body for GET
					 E3DB_Op_GetHttpUrl(op), E3DB_Op_GetHttpUrl(op), headers_string);
			}

			else
			{
				fprintf(stderr, "Unsupported method: %s\n", method);
				abort();
			}

			if (mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request)) != strlen(request))
			{
				fprintf(stderr, "Failed to set up HTTP Request.\n");
				exit(EXIT_FAILURE);
			}

			char buffer[1024];
			int bytes_received;

			do
			{
				bytes_received = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, sizeof(buffer));
				printf("Bytes received %d\n", bytes_received);
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
			} while (bytes_received > 0);

			// Pass the response data to E3DB_Op_FinishHttpState
			E3DB_Op_FinishHttpState(op, response_data.response_code, response_data.data, NULL, 0);
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

	return 0;
}
