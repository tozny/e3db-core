/*
 * simple_example.c
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 *
 *
 * This is a simple program showing an employee handbook
 * At this time this SDK does not support searching or sharing records
 * but other Tozny SDKs currently do and would be able to be used for searching and sharing data.
 *
 */

#include "e3db_client.h"
#include "e3db_client.c"
#include "sds.h"
#include "cJSON.h"

int main(void)
{
	// Load Up Client
	// See e3db.c file for examples on how to read this in from a file
	char *configFile = NULL;
	E3DB_Client *client = LoadClient(configFile);

	// Set up Record Type Bucket
	char *record_type = "d2c-encrypted-data";
	const char *EmployeeRecords[4];

	// ----------------------------------------- Rob Williams
	printf("Local Encryption Test:   %s\n\n", "");
	cJSON *data = cJSON_CreateObject();
	cJSON *meta = cJSON_CreateObject();
	char *payload = "{"
			"\"gatewayId\" : \"9999999\","
			"\"enqueuedTimestamp\" : 1707207541000,"
			"\"deviceId\" : \"coreId\","
			"\"appProperties\" : {"
			"\"deviceType\" : \"core\","
			"\"eventType\" : \"telemetry\","
			"\"dataType\" : \"location\""
			"},"
			"\"payload\": {"
			"\"zoneInfo\" : \"zone 1\","
			"\"timestamp\" : 1707901342000,"
			"\"coreLocation\": {"
			"\"x\" : 43.8,"
			"\"y\" : 45,"
			"\"z\" : 12"
			"}"
			"}"
			"}";

	// Data remains encrypted end to end
	cJSON_AddStringToObject(data, "payload", payload);

	// Data remains encrypted end to end
	// Fetch Access Key
	unsigned char *accessKey = FetchRecordAccessKey(client, record_type);
	// Encrypt Record
	E3DB_LocalRecord *encryptedRecord = EncryptRecord(client, (const char **)record_type, data, NULL, accessKey);
	printf("Local Encrypted Record: %s  \n\n", "");
	char *data_str = cJSON_Print(encryptedRecord->data);
	printf("\nData %s \n", data_str);
	char *plain_str = cJSON_Print(encryptedRecord->plain);
	printf("\nPlain Meta %s \n", plain_str);

	printf("Local Decryption Test: %s  \n\n", "");
	E3DB_LocalRecord *recordDecrypted = DecryptRecord(client, (const char **)record_type, encryptedRecord->data, encryptedRecord->plain, accessKey);
	data_str = cJSON_Print(recordDecrypted->data);
	printf("Local Decrypted Record:  %s \n\n", "");
	printf("\nData %s \n", data_str);
	plain_str = cJSON_Print(recordDecrypted->plain);
	printf("\nPlain Meta %s \n", plain_str);
	// Clean up
	cJSON_Delete(data);
	free(encryptedRecord);
	free(recordDecrypted);

	// Clean up
	if (configFile)
	{
		free(configFile);
	}

	E3DB_Client_Delete(client);
	return 0;
}
