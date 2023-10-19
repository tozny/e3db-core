/*
 * e3db_client.c
 *
 * Copyright (C) 2017-2023, Tozny, LLC.
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
			// Turn on for debugging
			// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
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

E3DB_Record *WriteRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta)
{
	// Set Up Curl to be used
	curl_global_init(CURL_GLOBAL_DEFAULT);

	// Step 1: Get Access Key
	E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);

	int responseCode = curl_run_op_dont_fail_with_response_code(op, 404);

	if (responseCode == 404)
	{
		// Path B: Access Key Does Not Exist
		// Create Access Key
		E3DB_Op *operationCreateAccessKey = E3DB_CreateAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type, (const char **)client->options->public_key);
		curl_run_op(operationCreateAccessKey);
		// Fetch Encrypted Access Key
		E3DB_Op_Delete(op);
		op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);
		curl_run_op(op);
		E3DB_Op_Delete(operationCreateAccessKey);
	}

	// Step 2: Decrypt Access Key
	E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(op);
	E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
	E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
	char *rawEAK = (char *)E3DB_EAK_GetEAK(eak);
	char *authPublicKey = (char *)E3DB_EAK_GetAuthPubKey(eak);
	unsigned char *ak = (unsigned char *)E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, op->client->options->private_key);

	// Write Record
	// E3DB_Op *op3 = E3DB_WriteRecord_Begin(client, record_type, data, meta, ak);
	E3DB_Op *op3 = E3DB_WriteRecord_Begin(client, record_type, data, meta, ak);
	curl_run_op(op3);

	// Get Result
	E3DB_WriteRecordsResult *result = E3DB_WriteRecords_GetResult(op3);
	// Create return item
	E3DB_Record *writtenRecord = (E3DB_Record *)malloc(sizeof(E3DB_Record));
	E3DB_RecordMeta *writtenMeta = (E3DB_RecordMeta *)malloc(sizeof(E3DB_RecordMeta));
	cJSON *recordWritten = result->json->child;
	char *child = (char *)malloc(sizeof(char));
	char *copy = cJSON_Print(recordWritten);
	child = strdup(copy);
	cJSON *recordCopy = cJSON_Parse(child);
	// Copy over Meta
	cJSON *metaObj = cJSON_GetObjectItem(recordCopy, "meta");
	if (metaObj == NULL || metaObj->type != cJSON_Object)
	{
		fprintf(stderr, "Error: meta field doesn't exist.\n");
		abort();
	}
	E3DB_GetRecordMetaFromJSON(metaObj, writtenMeta);
	writtenRecord->meta = (E3DB_RecordMeta *)malloc(sizeof(E3DB_RecordMeta));
	writtenRecord->meta = writtenMeta;
	// Copy over data
	cJSON *dataObj = cJSON_GetObjectItem(recordCopy, "data");
	if (dataObj == NULL || dataObj->type != cJSON_Object)
	{
		fprintf(stderr, "Error: Data field doesn't exist.\n");
		abort();
	}
	writtenRecord->data = (cJSON *)malloc(sizeof(cJSON));
	writtenRecord->data = dataObj;
	// Copy over signature
	cJSON *signObj = cJSON_GetObjectItem(recordCopy, "rec_sig");
	if (signObj == NULL)
	{
		fprintf(stderr, "Error: Signature field doesn't exist.\n");
		abort();
	}
	writtenRecord->rec_sig = cJSON_Print(signObj);

	// printf("kddhfjhsdjfhkjsdhfksd %s", cJSON_Print(record->data));
	E3DB_Op_Delete(op3);

	// there is mixing going on causing double frees. 
	if(op) {
		// E3DB_Op_Delete(op);
	}

	curl_global_cleanup();
	return writtenRecord;
}

/*
 * {ReadRecords}
 *
 */
E3DB_Record *ReadRecords(E3DB_Client *client, const char **all_record_ids, int argumentCount)
{
	E3DB_Record *records = (E3DB_Record *)malloc(sizeof(E3DB_Record) * (argumentCount - 1));

	for (int i = 0; i < argumentCount - 1; i++)
	{
		E3DB_Op *op = E3DB_ReadRecords_Begin(client, &all_record_ids[i], 1, NULL, 0);
		curl_run_op(op);

		E3DB_ReadRecordsResult *result = E3DB_ReadRecords_GetResult(op);
		E3DB_ReadRecordsResultIterator *it = E3DB_ReadRecordsResult_GetIterator(result);
		while (!E3DB_ReadRecordsResultIterator_IsDone(it))
		{
			// At this point we have encrypted data
			E3DB_RecordMeta *meta = E3DB_ReadRecordsResultIterator_GetMeta(it);
			E3DB_Legacy_Record *record = E3DB_ReadRecordsResultIterator_GetData(it);

			// Set the record meta
			records[i].meta = (E3DB_RecordMeta *)malloc(sizeof(E3DB_RecordMeta));
			// Set record ID
			const char *record_id = E3DB_RecordMeta_GetRecordId(meta);
			records[i].meta->record_id = (char *)malloc(strlen(record_id) + 1);
			strcpy(records[i].meta->record_id, record_id);
			// Set writer ID
			const char *writer_id = E3DB_RecordMeta_GetWriterId(meta);
			records[i].meta->writer_id = (char *)malloc(strlen(writer_id) + 1);
			strcpy(records[i].meta->writer_id, writer_id);
			// Set user ID
			const char *user_id = E3DB_RecordMeta_GetUserId(meta);
			records[i].meta->user_id = (char *)malloc(strlen(user_id) + 1);
			strcpy(records[i].meta->user_id, user_id);
			// Set type
			const char *type = E3DB_RecordMeta_GetType(meta);
			records[i].meta->type = (char *)malloc(strlen(type) + 1);
			strcpy(records[i].meta->type, type);
			// Set version
			const char *version = E3DB_RecordMeta_GetVersion(meta);
			records[i].meta->version = (char *)malloc(strlen(version) + 1);
			strcpy(records[i].meta->version, version);
			// Set created
			const char *created = E3DB_RecordMeta_GetCreated(meta);
			records[i].meta->created = (char *)malloc(strlen(created) + 1);
			strcpy(records[i].meta->created, created);
			// Set last modified
			const char *last_modified = E3DB_RecordMeta_GetLastModified(meta);
			records[i].meta->last_modified = (char *)malloc(strlen(last_modified) + 1);
			strcpy(records[i].meta->last_modified, last_modified);
			// Set last plain
			cJSON *plain = E3DB_RecordMeta_GetPlain(meta);
			records[i].meta->plain = cJSON_Duplicate(plain, 1);

			// Set up Access Keys Fetch
			E3DB_Op *eakOp = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)E3DB_RecordMeta_GetWriterId(meta), (const char **)E3DB_RecordMeta_GetUserId(meta), (const char **)E3DB_RecordMeta_GetUserId(meta), (const char **)E3DB_RecordMeta_GetType(meta));

			// Run access keys fetch
			curl_run_op(eakOp);

			E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(eakOp);
			E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
			E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
			char *rawEAK = (char *)E3DB_EAK_GetEAK(eak);
			char *authPublicKey = (char *)E3DB_EAK_GetAuthPubKey(eak);
			unsigned char *ak = (unsigned char *)E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, eakOp->client->options->private_key);

			// Decrypt the record data
			E3DB_RecordFieldIterator *f_it = E3DB_Record_GetFieldIterator(record);
			cJSON *decryptedData = cJSON_CreateObject();
			while (!E3DB_RecordFieldIterator_IsDone(f_it))
			{
				unsigned char *edata = (unsigned char *)E3DB_RecordFieldIterator_GetValue(f_it);
				const char *ddata = E3DB_RecordFieldIterator_DecryptValue(edata, ak);
				const char *name = E3DB_RecordFieldIterator_GetName(f_it);

				cJSON_AddStringToObject(decryptedData, name, ddata);

				free((void *)ddata);
				E3DB_RecordFieldIterator_Next(f_it);
			}
			records[i].data = decryptedData;
			char *rec_sig = E3DB_ReadRecordsResultIterator_GetRecSig(it);
			records[i].rec_sig = (char *)malloc(strlen(rec_sig) + 1);
			strcpy(records[i].rec_sig, rec_sig);

			E3DB_RecordFieldIterator_Delete(f_it);
			E3DB_ReadRecordsResultIterator_Next(it);
			cJSON_Delete(decryptedData);
			E3DB_Op_Delete(eakOp);
		}

		E3DB_ReadRecordsResultIterator_Delete(it);
		E3DB_Op_Delete(op);
		curl_global_cleanup();
	}
	return records;
}
