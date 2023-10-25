/*
 * e3db.c
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#include <pwd.h>
#include <unistd.h>
#include "e3db_client.h"
#include "e3db_client.c"
#include "sds.h"
#include "cJSON.h"

const char usage[] =
	"Usage: e3db [OPTIONS] COMMAND [ARGS...]\n"
	"Tozny E3DB Command Line Interface\n"
	"\n"
	"Available options:\n"
	"  -h, --help           print this help and exit\n"
	"      --version        output version info and exit\n"
	"\n"
	"Available commands:\n"
	" read-record          read records\n"
	" write-record         write record\n";

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

int cmdWrite(int argc, char **argv)
{
	// Not Enough Arguments
	if (argc < 2)
	{
		fputs(
			"Usage: e3db write [OPTIONS] -t TYPE -d @filename or JSON  -m @filename or JSON \n"
			"Write a record to E3DB.\n"
			"Pass in as JSON or fileName"
			"\n"
			"Available options:\n"
			"-c 		       config File Path\n"
			" -h, --help           print this help and exit\n",
			stderr);
		return 1;
	}

	// Grab the argument data
	const char *record_type = NULL;
	const char *data = NULL;
	const char *meta = NULL;
	cJSON *dataJSON = NULL;
	cJSON *metaJSON = NULL;
	char *configLocation = NULL;

	for (int i = 1; i <= argc; i++)
	{
		if (strcmp(argv[i], "-t") == 0)
		{
			if (i + 1 <= argc && argv[i + 1][0] != '-')
			{
				record_type = argv[i + 1];
			}
		}
		else if (strcmp(argv[i], "-d") == 0)
		{
			if (i + 1 <= argc && argv[i + 1][0] != '-')
			{
				data = argv[i + 1];
			}
		}
		else if (strcmp(argv[i], "-m") == 0)
		{
			if (i + 1 <= argc && argv[i + 1][0] != '-')
			{
				meta = argv[i + 1];
			}
		}
		else if (strcmp(argv[i], "-c") == 0)
		{
			configLocation = (char *)xmalloc(strlen(argv[i + 1]) + 1);
			strcpy(configLocation, argv[i + 1]);
		}
	}

	// Load up the client
	E3DB_Client *client;
	if (configLocation)
	{
		client = E3DB_Client_New(load_config(configLocation + 1));
	}
	else
	{
		client = E3DB_Client_New(load_config(NULL));
	}

	if (record_type == NULL || data == NULL || meta == NULL)
	{
		printf("Record Type(-t) or Meta(-m) or Data(-d) are not provided.\n");
		return 0;
	}

	// Read in from File or JSON Blob for Data
	if (data[0] == '@')
	{
		// Case File
		FILE *fp = fopen(data + 1, "r");
		if (fp == NULL)
		{
			printf("Error %s ", ": Unable to open the file.\n");
			return 1;
		}

		// read the file contents into a string
		char buffer[5024];
		fread(buffer, 1, sizeof(buffer), fp);
		fclose(fp);

		// parse the JSON data
		cJSON *json = cJSON_Parse(buffer);
		if (json == NULL)
		{
			const char *error_ptr = cJSON_GetErrorPtr();
			if (error_ptr != NULL)
			{
				printf("Error: %s\n", error_ptr);
			}
			cJSON_Delete(json);
			return 1;
		}
		dataJSON = json;
	}
	else
	{
		// Case JSON
		cJSON *json = cJSON_Parse(data);
		if (json == NULL)
		{
			const char *error_ptr = cJSON_GetErrorPtr();
			if (error_ptr != NULL)
			{
				printf("Error: %s\n", error_ptr);
			}
			cJSON_Delete(json);
			return 1;
		}
		dataJSON = json;
	}
	// Read in from File or JSON Blob for Meta
	if (meta[0] == '@')
	{
		// Case File
		FILE *fp = fopen(meta + 1, "r");
		if (fp == NULL)
		{
			printf("Error %s ", ": Unable to open the file.\n");
			return 1;
		}

		// read the file contents into a string
		char buffer[5024];
		fread(buffer, 1, sizeof(buffer), fp);
		fclose(fp);

		// parse the JSON data
		cJSON *json = cJSON_Parse(buffer);
		if (json == NULL)
		{
			const char *error_ptr = cJSON_GetErrorPtr();
			if (error_ptr != NULL)
			{
				printf("Error: %s\n", error_ptr);
			}
			cJSON_Delete(json);
			return 1;
		}
		metaJSON = json;
	}
	else
	{
		// Case JSON
		cJSON *json = cJSON_Parse(meta);
		if (json == NULL)
		{
			const char *error_ptr = cJSON_GetErrorPtr();
			if (error_ptr != NULL)
			{
				printf("Error: %s\n", error_ptr);
			}
			cJSON_Delete(json);
			return 1;
		}
		metaJSON = json;
	}
	// Write the Record
	E3DB_Record *record = WriteRecord(client, (const char **)record_type, dataJSON, metaJSON);
	printf("\n\nRecord ID: %s\n", record->meta->record_id);
	printf("Record Type: %s\n", record->meta->type);

	char *recordPlain = cJSON_Print(record->meta->plain);
	printf("Record Plain: %s\n", recordPlain);
	free(recordPlain);

	char *recordData = cJSON_Print(record->data);
	printf("Record Data:  %s\n", recordData);
	free(recordData);

	printf("Record Created: %s\n", record->meta->created);
	printf("Record Last Modified: %s\n", record->meta->last_modified);
	printf("Record User ID: %s\n", record->meta->user_id);
	printf("Record Version: %s\n", record->meta->version);
	printf("Record Writer ID: %s\n", record->meta->writer_id);

	// Clean Up Memory
	if (configLocation)
	{
		free(configLocation);
	}
	E3DB_Client_Delete(client);
	E3DB_FreeRecordMeta(record->meta);
	cJSON_Delete(record->data);
	free(record->rec_sig);
	free(record);
	if (dataJSON)
	{
		cJSON_Delete(dataJSON);
	}
	return 0;
}

int cmdRead(int argc, char **argv)
{
	if (argc < 2)
	{
		fputs(
			"Usage: e3db read [OPTIONS] RECORD_ID...\n"
			"Read one or more records from E3DB.\n"
			"\n"
			"Available options:\n"
			"-c 		       config File Path\n"
			"  -h, --help           print this help and exit\n",
			stderr);
		return 1;
	}

	char *configLocation = NULL;
	// Check if a config location was passed in
	if (!strcmp(argv[1], "-c"))
	{
		configLocation = (char *)xmalloc(strlen(argv[2]) + 1);
		strcpy(configLocation, argv[2]);
	}

	// Load up the client
	E3DB_Client *client;
	if (configLocation)
	{
		client = E3DB_Client_New(load_config(configLocation + 1));
	}
	else
	{
		client = E3DB_Client_New(load_config(NULL));
	}

	// Set up parameters
	const char **all_record_ids = NULL;
	int count = 0;
	if (!configLocation)
	{
		all_record_ids = (const char **)&argv[1]; // Mem for all_record_ids -> cli args managed by the op sys
		count = argc - 1;
	}
	else
	{
		all_record_ids = (const char **)&argv[3];
		count = argc - 3;
	}

	E3DB_Record *records = ReadRecords(client, all_record_ids, count);

	// Display Returned Data
	for (int i = 0; i < count; i++)
	{
		printf("\n%-20s %s\n", "record_id:", records[i].meta->record_id);
		printf("\n%-20s %s\n", "record_type:", records[i].meta->type);
		printf("\n%-20s %s\n", "writer_id:", records[i].meta->writer_id);
		printf("\n%-20s %s\n", "user_id:", records[i].meta->user_id);
		printf("\n%-20s %s\n", "version:", records[i].meta->version);
		printf("\n%-20s %s\n", "created:", records[i].meta->created);
		printf("\n%-20s %s\n", "last_modified:", records[i].meta->last_modified);
		printf("\n%-20s %s\n", "rec_sig:", records[i].rec_sig);

		char *plain_str = cJSON_Print(records[i].meta->plain);
		printf("\n%-20s \n%s\n", "plain:", plain_str);
		free(plain_str);

		char *data_str = cJSON_Print(records[i].data);
		printf("\n%-20s \n%s\n", "data:", data_str);
		free(data_str);
	}

	// Clean Up Memory
	if (configLocation)
	{
		free(configLocation);
	}
	E3DB_CleanupRecords(records, count);
	E3DB_Client_Delete(client);
	return 0;
}

int main(int argc, char **argv)
{
	printf("e3db-cli\n");
	printf("E3DB Command Line Interface\n");

	// Catches the help option
	if (argc < 2)
	{
		fputs(usage, stderr);
		return 1;
	}

	// Read Record
	if (!strcmp(argv[1], "read-record"))
	{
		int records_read = cmdRead(argc - 1, &argv[1]);
		return records_read;
	}
	// Write Record
	else if (!strcmp(argv[1], "write-record"))
	{
		int records_written = cmdWrite(argc - 1, argv);
		return records_written;
	}
	else
	{
		fputs(usage, stderr);
		return 1;
	}
}
