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
#include "e3db_core.h"
#include "curl.h"
#include "e3db_core.c"
#include "e3db_client.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

#include "sodium.h"

/*
 * {WriteRecord}
 *
 */

E3DB_Record *WriteRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta)
{

	// Step 1: Get Access Key
	E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)client->options->client_id, (const char **)record_type);

	int responseCode = curl_run_op_with_expected_response_code(op, 404);

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

	// ak needs to be deallocated at some point?
	unsigned char *ak = (unsigned char *)E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, op->client->options->private_key);

	// Write Record
	E3DB_Op_Delete(op);
	op = E3DB_WriteRecord_Begin(client, record_type, data, meta, ak);
	curl_run_op(op);

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
		curl_run_op(op);

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
