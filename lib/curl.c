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

	return 0;
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
    .on_headers_complete = on_headers_complete,
};

int mbedtls_run_op(E3DB_Op *op)
{
	// Set up objects
	mbedtls_net_context server_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *hostname = "api.e3db.com"; // TODO replace with E3DB_Op_GetHostName once tested
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

			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
			size_t lengthOfhEders = E3DB_HttpHeaderList_GetLength(headers);
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
				header = E3DB_HttpHeader_GetNext(header);
			}

			if (!strcmp(method, "POST"))
			{
				const char *post_body = E3DB_Op_GetHttpBody(op);
				int ret = snprintf(request, MAX_REQUEST_SIZE,
						   "POST %s HTTP/1.1\r\n"
						   "Host: api.e3db.com\r\n" // Use only the hostname
						   "Content-Length: %zu\r\n"
						   "%s\r\n" // Authorization header
						   "%s",    // Request body
						   E3DB_Op_GetHttpUrl(op), strlen(post_body), headers_string, post_body);

				if (ret < 0 || ret >= MAX_REQUEST_SIZE - 1) // -1 to leave room for the null terminator
				{
					fprintf(stderr, "Error constructing request.\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (!strcmp(method, "GET"))
			{
				int ret = snprintf(request, MAX_REQUEST_SIZE,
						   "GET %s HTTP/1.1\r\n"
						   "Host: api.e3db.com\r\n" // Use only the hostname
						   "%s"			    // Additional headers if needed
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
			if (mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request)) != strlen(request))
			{
				fprintf(stderr, "Failed to set up HTTP Request.\n");
				exit(EXIT_FAILURE);
			}
			free(response_data.data);
			response_data.data = NULL;
			// Allocate memory for the response buffer
			char *buffer = (char *)xmalloc(MAX_BUFFER_SIZE);
			// Check for allocation errors
			if (buffer == NULL)
			{
				fprintf(stderr, "Memory allocation error.\n");
				exit(EXIT_FAILURE);
			}
			int bytes_received = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, MAX_BUFFER_SIZE);
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
			// TODO Find out why the body does not get reset in response_data.data
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
			// Intermediate fix for above issue on TODO
			const char *body_start = strstr(buffer, "\r\n\r\n");
			size_t body_length = strlen(body_start + 4);  // Skip the "\r\n\r\n"
			char *body = (char *)malloc(body_length + 1); // +1 for null terminator
			strcpy(body, body_start + 4);

			// Pass the response data to E3DB_Op_FinishHttpState
			E3DB_Op_FinishHttpState(op, response_data.response_code, body, NULL, 0);
			// Free memory at the end
			free(headers_string);
			free(request);
		}
	}
	// Clean up mbedtls components
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);

	return 0;
}

int mbedtls_run_op_with_expected_response_code(E3DB_Op *op, long expected_response_code)
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

			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
			size_t lengthOfhEders = E3DB_HttpHeaderList_GetLength(headers);
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
				header = E3DB_HttpHeader_GetNext(header);
			}

			if (!strcmp(method, "POST"))
			{
				const char *post_body = E3DB_Op_GetHttpBody(op);
				int ret = snprintf(request, MAX_REQUEST_SIZE,
						   "POST %s HTTP/1.1\r\n"
						   "Host: api.e3db.com\r\n" // Use only the hostname
						   "Content-Length: %zu\r\n"
						   "%s\r\n" // Authorization header
						   "%s",    // Request body
						   E3DB_Op_GetHttpUrl(op), strlen(post_body), headers_string, post_body);

				if (ret < 0 || ret >= MAX_REQUEST_SIZE - 1) // -1 to leave room for the null terminator
				{
					fprintf(stderr, "Error constructing request.\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (!strcmp(method, "GET"))
			{
				int ret = snprintf(request, MAX_REQUEST_SIZE,
						   "GET %s HTTP/1.1\r\n"
						   "Host: api.e3db.com\r\n" // Use only the hostname
						   "%s"			    // Additional headers if needed
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
			if (mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request)) != strlen(request))
			{
				fprintf(stderr, "Failed to set up HTTP Request.\n");
				exit(EXIT_FAILURE);
			}
			free(response_data.data);
			response_data.data = NULL;
			// Allocate memory for the response buffer
			char *buffer = (char *)xmalloc(MAX_BUFFER_SIZE);
			// Check for allocation errors
			if (buffer == NULL)
			{
				fprintf(stderr, "Memory allocation error.\n");
				exit(EXIT_FAILURE);
			}
			int bytes_received = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, MAX_BUFFER_SIZE);
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
			// TODO Find out why the body does not get reset in response_data.data
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
			// Intermediate fix for above issue on TODO
			const char *body_start = strstr(buffer, "\r\n\r\n");
			size_t body_length = strlen(body_start + 4);  // Skip the "\r\n\r\n"
			char *body = (char *)malloc(body_length + 1); // +1 for null terminator
			strcpy(body, body_start + 4);
			if (response_data.response_code == expected_response_code)
			{
				mbedtls_ssl_close_notify(&ssl);
				mbedtls_net_free(&server_fd);
				mbedtls_x509_crt_free(&cacert);
				mbedtls_ssl_free(&ssl);
				mbedtls_ssl_config_free(&conf);
				return expected_response_code;
			}
			// Pass the response data to E3DB_Op_FinishHttpState
			E3DB_Op_FinishHttpState(op, response_data.response_code, body, NULL, 0);
			// Free memory at the end
			free(headers_string);
			free(request);
		}
	}
	// Clean up mbedtls components
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);

	return 0;
}
