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
	E3DB_Client *client = load_client(configFile);

	// Set up Record Type Bucket
	char *record_type = "employees";
	const char *EmployeeRecords[4];

	// ----------------------------------------- Rob Williams
	printf("Local Encryption Test:   %s\n\n", "");
	cJSON *data = cJSON_CreateObject();
	cJSON *meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	cJSON_AddStringToObject(data, "First Name", "Rob");
	cJSON_AddStringToObject(data, "Last Name", "Williams");
	cJSON_AddStringToObject(data, "Phone Number", "111-222-3333");
	cJSON_AddStringToObject(data, "Hourly Pay", "20");
	cJSON_AddStringToObject(data, "Max Hours Allowed", "10");

	// Meta are Searchable terms stored in plain text for indexing and fast retrieval
	cJSON_AddStringToObject(meta, "Type", "Employee");
	cJSON_AddStringToObject(meta, "Company", "Tozny");
	cJSON_AddStringToObject(meta, "Team", "Hardware");

	// Fetch Access Key
	unsigned char *accessKey = (unsigned char *)xmalloc(32);
	accessKey = FetchRecordAccessKey(client, record_type);
	// Encrypt Record
	E3DB_LocalRecord *encryptedRecord = EncryptRecord(client, (const char **)record_type, data, meta, accessKey);
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
	cJSON_Delete(meta);
	free(encryptedRecord);
	free(recordDecrypted);

	// ----------------------------------------- Kate Williams
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	cJSON_AddStringToObject(data, "First Name", "Katie");
	cJSON_AddStringToObject(data, "Last Name", "Williams");
	cJSON_AddStringToObject(data, "Phone Number", "111-222-3333");
	cJSON_AddStringToObject(data, "Hourly Pay", "20");
	cJSON_AddStringToObject(data, "Max Hours Allowed", "10");

	// Meta are Searchable terms stored in plain text for indexing and fast retrieval
	cJSON_AddStringToObject(meta, "Type", "Employee");
	cJSON_AddStringToObject(meta, "Company", "Tozny");
	cJSON_AddStringToObject(meta, "Team", "Software");
	E3DB_Record *record = WriteRecord(client, (const char **)record_type, data, meta);
	EmployeeRecords[0] = strdup(record->meta->record_id);

	// Clean up
	cJSON_Delete(data);
	E3DB_FreeRecordMeta(record->meta);
	cJSON_Delete(record->data);
	free(record->rec_sig);
	free(record);

	// -----------------------------------------  Liliana Perez
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	cJSON_AddStringToObject(data, "First Name", "Liliana");
	cJSON_AddStringToObject(data, "Last Name", "Perez");
	cJSON_AddStringToObject(data, "Phone Number", "111-222-3333");
	cJSON_AddStringToObject(data, "Hourly Pay", "5");
	cJSON_AddStringToObject(data, "Max Hours Allowed", "30");

	// Meta are Searchable terms stored in plain text for indexing and fast retrieval
	cJSON_AddStringToObject(meta, "Type", "Employee");
	cJSON_AddStringToObject(meta, "Company", "Tozny");
	cJSON_AddStringToObject(meta, "Team", "Sales");

	record = WriteRecord(client, (const char **)record_type, data, meta);
	EmployeeRecords[1] = strdup(record->meta->record_id);

	// Clean up
	cJSON_Delete(data);
	E3DB_FreeRecordMeta(record->meta);
	cJSON_Delete(record->data);
	free(record->rec_sig);
	free(record);

	// ----------------------------------------- Jason Smith
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	cJSON_AddStringToObject(data, "First Name", "Jason");
	cJSON_AddStringToObject(data, "Last Name", "Smith");
	cJSON_AddStringToObject(data, "Phone Number", "111-222-3333");
	cJSON_AddStringToObject(data, "Hourly Pay", "1");
	cJSON_AddStringToObject(data, "Max Hours Allowed", "10");

	// Meta are Searchable terms stored in plain text for indexing and fast retrieval
	cJSON_AddStringToObject(meta, "Type", "Employee");
	cJSON_AddStringToObject(meta, "Company", "Tozny");
	cJSON_AddStringToObject(meta, "Team", "Design");

	record = WriteRecord(client, (const char **)record_type, data, meta);
	EmployeeRecords[2] = strdup(record->meta->record_id);

	// Clean up
	cJSON_Delete(data);
	E3DB_FreeRecordMeta(record->meta);
	cJSON_Delete(record->data);
	free(record->rec_sig);
	free(record);

	// -----------------------------------------  Meredith Yang
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	cJSON_AddStringToObject(data, "First Name", "Meredith");
	cJSON_AddStringToObject(data, "Last Name", "Yang");
	cJSON_AddStringToObject(data, "Phone Number", "111-222-3333");
	cJSON_AddStringToObject(data, "Hourly Pay", "15");
	cJSON_AddStringToObject(data, "Max Hours Allowed", "30");

	// Meta are Searchable terms stored in plain text for indexing and fast retrieval
	cJSON_AddStringToObject(meta, "Type", "Employee");
	cJSON_AddStringToObject(meta, "Company", "Tozny");
	cJSON_AddStringToObject(meta, "Team", "Hardware");
	record = WriteRecord(client, (const char **)record_type, data, meta);
	EmployeeRecords[3] = strdup(record->meta->record_id);

	// Clean up
	cJSON_Delete(data);
	E3DB_FreeRecordMeta(record->meta);
	cJSON_Delete(record->data);
	free(record->rec_sig);
	free(record);

	// View all Records
	E3DB_Record *records = ReadRecords(client, EmployeeRecords, 4);

	// Display Returned Data
	for (int i = 0; i < 4; i++)
	{
		printf("\nEmployee %d", i + 1);

		char *plain_str = cJSON_Print(records[i].meta->plain);
		printf("\n%-20s \n%s\n", "plain:", plain_str);
		free(plain_str);

		char *data_str = cJSON_Print(records[i].data);
		printf("\n%-20s \n%s\n", "data:", data_str);
		free(data_str);
	}

	// Clean up
	if (configFile)
	{
		free(configFile);
	}

	// Free each element of the EmployeeRecords id array
	for (int i = 0; i < 4; i++)
	{
		free((void *)EmployeeRecords[i]); // Cast to void* because the array is of type const char*
		EmployeeRecords[i] = NULL;
	}
	E3DB_CleanupRecords(records, 4);
	E3DB_Client_Delete(client);
	return 0;
}
