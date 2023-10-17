/*
 * main.c
 *
 * Copyright (C) 2023, Tozny.
 * All Rights Reserved.
 */

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "e3db_core.h"
#include "e3db_core.c"

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
    " write-record                write record\n";

int cmdWrite(int argc, char **argv)
{
	if (argc < 2)
	{
		fputs(
		    "Usage: e3db write [OPTIONS] -t TYPE -d @filename or JSON  -m @filename or JSON \n"
		    "Write a record to E3DB.\n"
		    "Example: write-record -t hello -d '{hello: hello}'  -m '{english : language}' "
		    "Pass in as JSON or fileName"
		    "\n"
		    "Available options:\n"
		    "  -h, --help           print this help and exit\n",
		    stderr);
		return 1;
	}
	// E3DB_Client *client = E3DB_Client_New(load_config());

	const char *record_type = NULL;
	const char *data = NULL;
	const char *meta = NULL;
	cJSON *dataJSON = NULL;
	cJSON *metaJSON = NULL;

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
	}

	if (record_type == NULL || data == NULL || meta == NULL)
	{
		printf("Record Type(-t) or Meta(-m) or Data(-d) are not provided.\n");
		return 0;
	}

	if (data[0] == '@')
	{
		// Case File
		// open the file
		FILE *fp = fopen(data + 1, "r");
		if (fp == NULL)
		{
			printf("Error %s ", ": Unable to open the file.\n");
			return 1;
		}

		// read the file contents into a string
		char buffer[1024];
		int len = fread(buffer, 1, sizeof(buffer), fp);
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
		printf("%s", "inside else");
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

	printf("\nDATA JSON %s \n", cJSON_Print(dataJSON));

	if (meta[0] == '@')
	{
		// Case File
		// open the file
		FILE *fp = fopen(meta + 1, "r");
		if (fp == NULL)
		{
			printf("Error %s ", ": Unable to open the file.\n");
			return 1;
		}

		// read the file contents into a string
		char buffer[1024];
		int len = fread(buffer, 1, sizeof(buffer), fp);
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

	// E3DB_Client_Delete(client);

	return 0;
}

int main(int argc, char **argv)
{
	printf("e3db-cli\n");
	printf("E3DB Command Line Interface\n");
	printf("Instructions: \n");

	// Catches the help option
	if (argc < 2)
	{
		fputs(usage, stderr);
		return 1;
	}

	if (!strcmp(argv[1], "read-record"))
	{
		// int records_read = cmdRead(argc - 1, &argv[1]);
		// return records_read;
	}
	else if (!strcmp(argv[1], "write-record"))
	{
		// int records_written = cmdWrite(argc - 1, argv);
		// return records_written;
	}
	else
	{
		fputs(usage, stderr);
		return 1;
	}
}
