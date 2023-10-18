/*
 * e3db_client.c
 *
 * Copyright (C) 2023, Tozny, LLC.
 * All Rights Reserved.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "utlist.h"
#include "sds.h"
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "e3db_core.h"
#include "e3db_core.c"
#include "e3db_client.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

#include "sodium.h"
/* Callback function for libcurl to read data that should be supplied
 * as the body in an HTTP POST/PUT/etc request, from an OpenSSL BIO.
 * Returns the number of bytes read. */
size_t read_body(void *ptr, size_t size, size_t nmemb, BIO *bio)
{
	size_t len = size * nmemb;
	int result;

	if ((result = BIO_read(bio, ptr, len)) < 0)
	{
		fprintf(stderr, "read_body: BIO_read failed\n");
		abort();
	}

	return (size_t)result;
}

/* Callback function for libcurl to write data received from an HTTP
 * request to an OpenSSL BIO. Returns the number of bytes written. */
size_t write_body(void *ptr, size_t size, size_t nmemb, BIO *bio)
{
	size_t len = size * nmemb;
	int result;

	if ((result = BIO_write(bio, ptr, len)) < 0)
	{
		fprintf(stderr, "write_body: BIO_write failed\n");
		abort();
	}

	return (size_t)result;
}

/* Complete an E3DB operation using libcurl for HTTP requests. */
int curl_run_op(E3DB_Op *op)
{
	CURL *curl;

	if ((curl = curl_easy_init()) == NULL)
	{
		fprintf(stderr, "Fatal: Curl initialization failed.\n");
		exit(1);
	}

	while (!E3DB_Op_IsDone(op))
	{
		if (E3DB_Op_IsHttpState(op))
		{
			curl_easy_reset(curl);

			const char *method = E3DB_Op_GetHttpMethod(op);
			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
			BIO *write_bio = BIO_new(BIO_s_mem());

			struct curl_slist *chunk = NULL;
			E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

			while (header != NULL)
			{
				sds header_text = sdscatprintf(sdsempty(), "%s: %s",
							       E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
				chunk = curl_slist_append(chunk, header_text);
				sdsfree(header_text);

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
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_bio);

			CURLcode res = curl_easy_perform(curl);
			if (res != CURLE_OK)
			{
				fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
			}
			long response_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

			char *body;
			BIO_write(write_bio, "\0", 1);
			BIO_get_mem_data(write_bio, &body);
			E3DB_Op_FinishHttpState(op, response_code, body, NULL, 0);
			printf("\nBody Returned %s\n", body);
			BIO_free_all(write_bio);
			curl_slist_free_all(chunk);
		}
	}

	curl_easy_cleanup(curl);
	return 0;
}

/* Complete an E3DB operation using libcurl for HTTP requests. */
int curl_run_op_dont_fail_with_response_code(E3DB_Op *op, long response_code_not_errored)
{
	CURL *curl;

	if ((curl = curl_easy_init()) == NULL)
	{
		fprintf(stderr, "Fatal: Curl initialization failed.\n");
		exit(1);
	}

	while (!E3DB_Op_IsDone(op))
	{
		if (E3DB_Op_IsHttpState(op))
		{
			curl_easy_reset(curl);

			const char *method = E3DB_Op_GetHttpMethod(op);
			E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
			BIO *write_bio = BIO_new(BIO_s_mem());

			struct curl_slist *chunk = NULL;
			E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

			while (header != NULL)
			{
				sds header_text = sdscatprintf(sdsempty(), "%s: %s",
							       E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
				chunk = curl_slist_append(chunk, header_text);
				sdsfree(header_text);

				header = E3DB_HttpHeader_GetNext(header);
			}

			if (!strcmp(method, "POST"))
			{
				printf("%s", "IF POST");
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
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_bio);

			CURLcode res = curl_easy_perform(curl);
			if (res != CURLE_OK)
			{
				fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
			}
			long response_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
			if (response_code == response_code_not_errored)
			{
				curl_easy_cleanup(curl);
				return response_code_not_errored;
			}

			char *body;
			BIO_write(write_bio, "\0", 1);
			BIO_get_mem_data(write_bio, &body);
			E3DB_Op_FinishHttpState(op, response_code, body, NULL, 0);
			BIO_free_all(write_bio);
			curl_slist_free_all(chunk);
		}
	}

	curl_easy_cleanup(curl);
	return 0;
}

/*
 * {WriteRecord}
 *
 */

void WriteRecord(E3DB_Record *record, E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta)
{
	// Set Up Curl to be used
	curl_global_init(CURL_GLOBAL_DEFAULT);

	// Step 1: Get Access Key
	E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, client->options->client_id, client->options->client_id, client->options->client_id, record_type);

	int responseCode = curl_run_op_dont_fail_with_response_code(op, 404);

	if (responseCode == 404)
	{
		// Path B: Access Key Does Not Exist
		// Create Access Key
		E3DB_Op *operationCreateAccessKey = E3DB_CreateAccessKeys_Begin(client, client->options->client_id, client->options->client_id, client->options->client_id, record_type, client->options->public_key);
		curl_run_op(operationCreateAccessKey);
		// Fetch Encrypted Access Key
		op = E3DB_GetEncryptedAccessKeys_Begin(client, client->options->client_id, client->options->client_id, client->options->client_id, record_type);
		curl_run_op(op);
	}

	// Step 2: Decrypt Access Key
	E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(op);
	E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
	E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
	char *rawEAK = E3DB_EAK_GetEAK(eak);
	char *authPublicKey = E3DB_EAK_GetAuthPubKey(eak);
	unsigned char *ak = E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, op->client->options->private_key);
	printf("\nDECRYPTED AK %s \n", ak);

	// Write Record
	op = E3DB_WriteRecord_Begin(client, record_type, data, meta, ak);
	curl_run_op(op);

	// Get Results
	E3DB_WriteRecordsResult *result = E3DB_WriteRecords_GetResult(op);

	E3DB_Op_Delete(op);
	curl_global_cleanup();
}

/*
 * {ReadRecords}
 *
 */
void ReadRecords(E3DB_Record *records, E3DB_Client *client, const char **all_record_ids, int argumentCount)
{
	for (int i = 0; i < argumentCount - 1; i++)
	{
		const char **record_ids = (const char **)malloc(sizeof(const char *));
		record_ids[0] = all_record_ids[i];

		E3DB_Op *op = E3DB_ReadRecords_Begin(client, &all_record_ids[i], 1, NULL, 0);
		curl_run_op(op);

		E3DB_ReadRecordsResult *result = E3DB_ReadRecords_GetResult(op);
		E3DB_ReadRecordsResultIterator *it = E3DB_ReadRecordsResult_GetIterator(result);
		while (!E3DB_ReadRecordsResultIterator_IsDone(it))
		{
			// At this point we have encrypted data
			E3DB_RecordMeta *meta = E3DB_ReadRecordsResultIterator_GetMeta(it);
			E3DB_Legacy_Record *record = E3DB_ReadRecordsResultIterator_GetData(it);

			// Set up Access Keys Fetch
			E3DB_Op *eakOp = E3DB_GetEncryptedAccessKeys_Begin(client, E3DB_RecordMeta_GetWriterId(meta), E3DB_RecordMeta_GetUserId(meta), E3DB_RecordMeta_GetUserId(meta), E3DB_RecordMeta_GetType(meta));

			// Run access keys fetch
			curl_run_op(eakOp);

			E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(eakOp);
			E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
			E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
			char *rawEAK = E3DB_EAK_GetEAK(eak);
			char *authPublicKey = E3DB_EAK_GetAuthPubKey(eak);
			unsigned char *ak = E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, eakOp->client->options->private_key);
			printf("\nDECRYPTED AK %s\n", ak);

			E3DB_Record *decrypted_record = (E3DB_Record *)malloc(sizeof(E3DB_Record));
			decrypted_record->meta = meta;
			decrypted_record->rec_sig = E3DB_ReadRecordsResultIterator_GetRecSig(it);

			// Decrypt the record data
			E3DB_RecordFieldIterator *f_it = E3DB_Record_GetFieldIterator(record);
			cJSON *decryptedData = cJSON_CreateObject();
			while (!E3DB_RecordFieldIterator_IsDone(f_it))
			{
				unsigned char *edata = E3DB_RecordFieldIterator_GetValue(f_it);
				printf("\nedata: %s\n", edata);

				char *ddata = E3DB_RecordFieldIterator_DecryptValue(edata, ak);
				char *name = E3DB_RecordFieldIterator_GetName(f_it);

				cJSON_AddStringToObject(decryptedData, name, ddata);

				free(ddata);
				E3DB_RecordFieldIterator_Next(f_it);
			}
			decrypted_record->data = decryptedData;

			records[i] = *decrypted_record;
			// Print the record info
			printf("\nRECORD INFO FOR RECORD #%d:\n", i + 1);
			printf("\n%-20s %s\n", "record_id:", records[i].meta->record_id);
			printf("\n%-20s %s\n", "record_type:", records[i].meta->type);
			printf("\n%-20s %s\n", "writer_id:", records[i].meta->writer_id);
			printf("\n%-20s %s\n", "user_id:", records[i].meta->user_id);
			printf("\n%-20s %s\n", "version:", records[i].meta->version);
			printf("\n%-20s %s\n", "created:", records[i].meta->created);
			printf("\n%-20s %s\n", "last_modified:", records[i].meta->last_modified);
			printf("\n%-20s %s\n", "rec_sig:", records[i].rec_sig);
			printf("\n%-20s \n%s\n", "plain:", cJSON_Print(records[i].meta->plain));
			printf("\n%-20s \n%s\n", "data:", cJSON_Print(records[i].data));

			E3DB_RecordFieldIterator_Delete(f_it);
			E3DB_ReadRecordsResultIterator_Next(it);
		}

		E3DB_ReadRecordsResultIterator_Delete(it);
		E3DB_Op_Delete(op);
		curl_global_cleanup();
	}
}
