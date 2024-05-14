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
#include <stdbool.h>
#include <pwd.h>
#include <unistd.h>

#include "cJSON.h"
#include "utlist.h"
#include "sds.h"
#include "e3db_core.h"
#include "curl.h"
#include "e3db_core.c"
#include "e3db_client.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

#include "sodium.h"

/* Get the user's home directory.
 *
 */
sds get_home_dir(void)
{
	char *home;

	if ((home = getenv("HOME")) != NULL)
	{
		return sdsnew(home);
	}

	uid_t uid = getuid();
	struct passwd *pw = getpwuid(uid);

	if (pw == NULL)
	{
		fprintf(stderr, "Error: Unable to get user home directory.\n");
		exit(1);
	}

	return sdsnew(pw->pw_dir);
}

/* Read the JSON configuration from a file or hardcoded string*/
static void get_config_json(char *configLocation, sds *config)
{

	sds config_file = NULL;
	if (!configLocation)
	{
		config_file = sdscat(get_home_dir(), "/.tozny/e3db.json");
	}
	else
	{
		config_file = sdsnew(configLocation);
	}

	FILE *in;

	if ((in = fopen(config_file, "r")) == NULL)
	{
		fprintf(stderr, "Error: Unable to open E3DB configuration file.\n");
		exit(1);
	}

	while (!feof(in))
	{
		char buf[4096];
		size_t len;

		len = fread(buf, 1, sizeof(buf), in);
		*config = sdscatlen(*config, buf, len);
	}

	fclose(in);
	sdsfree(config_file);
}

/* Load the user's e3db configuration into an E3DB_ClientOptions. */
E3DB_ClientOptions *load_config(char *configLocation)
{
	// Get JSON text from file or hardcoded string
	sds config = sdsempty();
	get_config_json(configLocation, &config);
	cJSON *json = cJSON_Parse(config);
	if (json == NULL)
	{
		fprintf(stderr, "Error: Unable to parse E3DB configuration file.\n");
		exit(1);
	}

	E3DB_ClientOptions *opts = E3DB_ClientOptions_New();
	cJSON *api_key, *api_secret, *client_id, *private_key, *public_key, *private_signing_key;

	api_key = cJSON_GetObjectItem(json, "api_key_id");
	if (api_key == NULL || api_key->type != cJSON_String)
	{
		fprintf(stderr, "Error: Missing 'api_key_id' key in configuration file.\n");
		exit(1);
	}

	api_secret = cJSON_GetObjectItem(json, "api_secret");
	if (api_secret == NULL || api_secret->type != cJSON_String)
	{
		fprintf(stderr, "Error: Missing 'api_secret' key in configuration file.\n");
		exit(1);
	}

	client_id = cJSON_GetObjectItem(json, "client_id");
	if (client_id == NULL || client_id->type != cJSON_String)
	{
		fprintf(stderr, "Error: Missing 'client_id' key in configuration file.\n");
		exit(1);
	}

	private_key = cJSON_GetObjectItem(json, "private_key");
	if (private_key == NULL || private_key->type != cJSON_String)
	{
		fprintf(stderr, "Error: Missing 'private_key' key in configuration file.\n");
		exit(1);
	}

	public_key = cJSON_GetObjectItem(json, "public_key");
	if (public_key == NULL || public_key->type != cJSON_String)
	{
		fprintf(stderr, "Error: Missing 'public_key' key in configuration file.\n");
		exit(1);
	}

	private_signing_key = cJSON_GetObjectItem(json, "private_signing_key");
	if (private_signing_key == NULL || private_signing_key->type != cJSON_String)
	{
		fprintf(stderr, "Error: Missing 'private_signing_key' key in configuration file.\n");
		exit(1);
	}

	E3DB_ClientOptions_SetApiKey(opts, api_key->valuestring);
	E3DB_ClientOptions_SetApiSecret(opts, api_secret->valuestring);
	E3DB_ClientOptions_SetClientID(opts, client_id->valuestring);
	E3DB_ClientOptions_SetPrivateKey(opts, private_key->valuestring);
	E3DB_ClientOptions_SetPublicKey(opts, public_key->valuestring);
	E3DB_ClientOptions_SetPrivateSigningKey(opts, private_signing_key->valuestring);

	sdsfree(config);
	cJSON_Delete(json);

	return opts;
}

E3DB_Client *LoadClient(char *configLocation)
{
	return E3DB_Client_New(load_config(configLocation));
}

/*
 * {WriteRecord}
 *
 */

E3DB_Record *WriteRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta)
{

	// Step 1: Get Access Key
	E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);

	int responseCode = mbedtls_run_op_with_expected_response_code(op, 404);

	if (responseCode == 404)
	{
		// Path B: Access Key Does Not Exist
		// Create Access Key
		E3DB_Op *operationCreateAccessKey = E3DB_CreateAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type, (const char **)client->options->public_key);
		mbedtls_run_op(operationCreateAccessKey);
		// Fetch Encrypted Access Key
		E3DB_Op_Delete(op);
		op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);
		mbedtls_run_op(op);
		E3DB_Op_Delete(operationCreateAccessKey);
	}

	// Step 2: Decrypt Access Key
	E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(op);
	E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
	E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
	char *rawEAK = (char *)E3DB_EAK_GetEAK(eak);
	char *authPublicKey = (char *)E3DB_EAK_GetAuthPubKey(eak);

	// ak needs to be deallocated at some point?
	unsigned char *ak = (unsigned char *)E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, op->client->options->private_key);

	// Write Record
	E3DB_Op_Delete(op);
	op = E3DB_WriteRecord_Begin(client, record_type, data, meta, ak);
	mbedtls_run_op(op);

	free(eak->eak);
	free(eak->signer_id);
	free(eak->authorizer_id);
	free(ak);

	// Get Result
	E3DB_WriteRecordsResult *result = E3DB_WriteRecords_GetResult(op);
	// Create return item
	E3DB_Record *writtenRecord = (E3DB_Record *)xmalloc(sizeof(E3DB_Record));
	E3DB_RecordMeta *writtenMeta = (E3DB_RecordMeta *)xmalloc(sizeof(E3DB_RecordMeta));
	cJSON *recordWritten = result->json->child;
	char *copy = cJSON_Print(recordWritten);
	char *child = strdup(copy);
	cJSON *recordCopy = cJSON_Parse(child);
	// cleanup
	free(copy);
	free(child);

	// Copy over Meta
	cJSON *metaObj = cJSON_GetObjectItem(recordCopy, "meta");
	if (metaObj == NULL || metaObj->type != cJSON_Object)
	{
		fprintf(stderr, "Error: meta field doesn't exist.\n");
		abort();
	}

	// Deep copy metaObj
	cJSON *metaObjCopy = cJSON_Duplicate(metaObj, 1);

	E3DB_GetRecordMetaFromJSON(metaObjCopy, writtenMeta);
	cJSON_Delete(metaObjCopy);

	writtenRecord->meta = writtenMeta;

	// Copy over data
	cJSON *dataObj = cJSON_GetObjectItem(recordCopy, "data");
	if (dataObj == NULL || dataObj->type != cJSON_Object)
	{
		fprintf(stderr, "Error: Data field doesn't exist.\n");
		abort();
	}

	// deep copy
	writtenRecord->data = cJSON_Duplicate(dataObj, 1);

	// Copy over signature
	cJSON *signObj = cJSON_GetObjectItem(recordCopy, "rec_sig");
	if (signObj == NULL)
	{
		fprintf(stderr, "Error: Signature field doesn't exist.\n");
		abort();
	}
	writtenRecord->rec_sig = cJSON_Print(signObj);

	// cleanup
	cJSON_Delete(recordCopy);
	free(EAKIt);
	if (op)
	{
		E3DB_Op_Delete(op);
	}
	return writtenRecord;
}

/*
 * {ReadRecords}
 *
 */
E3DB_Record *ReadRecords(E3DB_Client *client, const char **all_record_ids, int recordCount)
{
	E3DB_Record *records = (E3DB_Record *)xmalloc(sizeof(E3DB_Record) * (recordCount));

	for (int i = 0; i < recordCount; i++)
	{
		E3DB_Op *op = E3DB_ReadRecords_Begin(client, &all_record_ids[i], 1, NULL, 0);
		mbedtls_run_op(op);

		E3DB_ReadRecordsResult *result = E3DB_ReadRecords_GetResult(op);
		E3DB_ReadRecordsResultIterator *it = E3DB_ReadRecordsResult_GetIterator(result);
		while (!E3DB_ReadRecordsResultIterator_IsDone(it))
		{
			// At this point we have encrypted data
			E3DB_RecordMeta *meta = E3DB_ReadRecordsResultIterator_GetMeta(it);
			E3DB_Legacy_Record *record = E3DB_ReadRecordsResultIterator_GetData(it);

			// Set the record meta
			records[i].meta = meta;

			// Set up Access Keys Fetch
			E3DB_Op *eakOp = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)E3DB_RecordMeta_GetWriterId(meta), (const char **)E3DB_RecordMeta_GetUserId(meta), (const char **)E3DB_RecordMeta_GetUserId(meta), (const char **)E3DB_RecordMeta_GetType(meta));

			// Run access keys fetch
			mbedtls_run_op(eakOp);

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
			records[i].rec_sig = (char *)xmalloc(strlen(rec_sig) + 1);
			strcpy(records[i].rec_sig, rec_sig);

			E3DB_RecordFieldIterator_Delete(f_it);
			E3DB_ReadRecordsResultIterator_Next(it);
			E3DB_Op_Delete(eakOp);
			free(eak->eak);
			free(eak->signer_id);
			free(eak->authorizer_id);
			free(EAKIt);
			free(ak);
		}

		E3DB_ReadRecordsResultIterator_Delete(it);
		E3DB_Op_Delete(op);
	}
	return records;
}

/*
 * {EncryptRecord}
 * Encrypts record with a cached access key and returns an encrypted record to use
 */

E3DB_LocalRecord *EncryptRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta, unsigned char *accesskey)
{
	// Write Record
	E3DB_Op *op = E3DB_EncryptRecord_Begin(client, record_type, data, meta, accesskey);
	// Get Result
	E3DB_EncryptRecordResult *result = E3DB_EncryptRecord_GetResult(op);
	// Create return item
	E3DB_LocalRecord *writtenRecord = (E3DB_LocalRecord *)xmalloc(sizeof(E3DB_LocalRecord));
	// Set data
	writtenRecord->plain = meta;
	writtenRecord->data = result->data;
	// cleanup
	if (op)
	{
		E3DB_Op_Delete(op);
	}
	return writtenRecord;
}

/*
 * {FetchRecordAccessKey}
 * Fetches a record access key for a user, or creates one to return
 */

unsigned char *FetchRecordAccessKey(E3DB_Client *client, char *record_type)
{
	// Step 1: Get Access Key
	E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);

	int responseCode = mbedtls_run_op_with_expected_response_code(op, 404);
	if (responseCode == 404)
	{
		// Path B: Access Key Does Not Exist
		// Create Access Key
		E3DB_Op *operationCreateAccessKey = E3DB_CreateAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type, (const char **)client->options->public_key);
		mbedtls_run_op(operationCreateAccessKey);
		// Fetch Encrypted Access Key
		E3DB_Op_Delete(op);
		op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);
		mbedtls_run_op(op);
		E3DB_Op_Delete(operationCreateAccessKey);
	}

	// Step 2: Decrypt Access Key
	E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(op);
	E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
	E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
	char *rawEAK = (char *)E3DB_EAK_GetEAK(eak);
	char *authPublicKey = (char *)E3DB_EAK_GetAuthPubKey(eak);
	char *ak = (char *)E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, op->client->options->private_key);
	// cleanup
	free(EAKIt);
	if (op)
	{
		E3DB_Op_Delete(op);
	}
	return (unsigned char *)ak;
}

/*
 * {DecryptRecord}
 *
 */
E3DB_LocalRecord *DecryptRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta, unsigned char *accesskey)
{
	E3DB_LocalRecord *record = (E3DB_LocalRecord *)xmalloc(sizeof(E3DB_LocalRecord));
	// Set the record meta
	record->plain = meta;
	E3DB_Legacy_Record *recordData = (E3DB_Legacy_Record *)xmalloc(sizeof(E3DB_Legacy_Record));
	recordData->json = data;
	// Decrypt the record data
	E3DB_RecordFieldIterator *f_it = E3DB_Record_GetFieldIterator(recordData);
	cJSON *decryptedData = cJSON_CreateObject();
	while (!E3DB_RecordFieldIterator_IsDone(f_it))
	{
		unsigned char *edata = (unsigned char *)E3DB_RecordFieldIterator_GetValue(f_it);
		const char *ddata = E3DB_RecordFieldIterator_DecryptValue(edata, accesskey);
		const char *name = E3DB_RecordFieldIterator_GetName(f_it);

		cJSON_AddStringToObject(decryptedData, name, ddata);

		free((void *)ddata);
		E3DB_RecordFieldIterator_Next(f_it);
	}
	record->data = decryptedData;
	E3DB_RecordFieldIterator_Delete(f_it);

	return record;
}
