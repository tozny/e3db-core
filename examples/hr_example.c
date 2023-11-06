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

#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include "e3db_client.h"
#include "e3db_client.c"
#include "sds.h"
#include "cJSON.h"

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
/* Load the user's e3db configuration into an E3DB_ClientOptions. */
E3DB_ClientOptions *load_config(char *configLocation)
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

	sds config = sdsempty();

	while (!feof(in))
	{
		char buf[4096];
		size_t len;

		len = fread(buf, 1, sizeof(buf), in);
		config = sdscatlen(config, buf, len);
	}

	fclose(in);
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

	sdsfree(config_file);
	sdsfree(config);
	cJSON_Delete(json);

	return opts;
}

int main(void)
{
	// Load Up Client
	// See e3db.c file for examples on how to read this in from a file
	char *configFile = NULL;
	E3DB_Client *client = E3DB_Client_New(load_config(configFile));
	printf("%s", "Loaded Client");

	// Set up Record Type Bucket
	char *record_type = "employees";
	printf("Record Type %s", record_type);
	const char *EmployeeRecords[4];

	// ----------------------------------------- Kate Williams
	cJSON *data = cJSON_CreateObject();
	cJSON *meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	printf("%s \n", "Writing Record 1");
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
	printf("Written Record: %s \n", cJSON_Print(record->data));
	printf("\n\nRecord ID: %s\n", record->meta->record_id);
	EmployeeRecords[0] = strdup(record->meta->record_id);

	// Clean up
	// cJSON_Delete(data);
	// E3DB_FreeRecordMeta(record->meta);
	// cJSON_Delete(record->data);
	// free(record->rec_sig);
	// free(record);

	// -----------------------------------------  Liliana Perez
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	printf("%s", "Writing Record 2");
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
	printf("Written Record: %s\n", cJSON_Print(record->data));
	printf("\n\nRecord ID: %s\n", record->meta->record_id);
	EmployeeRecords[1] = strdup(record->meta->record_id);

	// Clean up
	// cJSON_Delete(data);
	// E3DB_FreeRecordMeta(record->meta);
	// cJSON_Delete(record->data);
	// free(record->rec_sig);
	// free(record);

	// ----------------------------------------- Jason Smith
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	printf("%s", "Writing Record 3");
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
	printf("Written Record: %s", cJSON_Print(record->data));
	printf("\n\nRecord ID: %s\n", record->meta->record_id);
	EmployeeRecords[2] = strdup(record->meta->record_id);

	// Clean up
	// cJSON_Delete(data);
	// E3DB_FreeRecordMeta(record->meta);
	// cJSON_Delete(record->data);
	// free(record->rec_sig);
	// free(record);

	// -----------------------------------------  Meredith Yang
	data = cJSON_CreateObject();
	meta = cJSON_CreateObject();

	// Data remains encrypted end to end
	printf("%s", "Writing Record 4");
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
	printf("Written Record: %s", cJSON_Print(record->data));
	printf("\n\nRecord ID: %s\n", record->meta->record_id);
	EmployeeRecords[3] = strdup(record->meta->record_id);

	// // Clean up
	// cJSON_Delete(data);
	// E3DB_FreeRecordMeta(record->meta);
	// cJSON_Delete(record->data);
	// free(record->rec_sig);
	// free(record);

	// View all Records
	printf("%s", "Reading Record Starts now");
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
