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
