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

#include "e3db_core.h"
#include "e3db_client.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

#include "sodium.h"

/*
 * Client Options
 */

typedef struct _E3DB_ClientOptions E3DB_ClientOptions;

E3DB_ClientOptions *E3DB_ClientOptions_New(void);
void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts);

void E3DB_ClientOptions_SetApiUrl(E3DB_ClientOptions *opts, const char *url);
void E3DB_ClientOptions_SetApiKey(E3DB_ClientOptions *opts, const char *api_key);
void E3DB_ClientOptions_SetApiSecret(E3DB_ClientOptions *opts, const char *api_secret);
void E3DB_ClientOptions_SetClientID(E3DB_ClientOptions *opts, const char *client_id);
void E3DB_ClientOptions_SetPrivateKey(E3DB_ClientOptions *opts, const char *private_key);
void E3DB_ClientOptions_SetPublicKey(E3DB_ClientOptions *opts, const char *public_key);

/*
 * Client
 */

struct _E3DB_Client
{
	E3DB_ClientOptions *options;
	sds access_token;
	// TODO: Add cached JWT from auth service.
	// TODO: If we add mutable state (like the JWT above), also add a lock
	// so that concurrent access via multiple operations in flight is safe.
};

/* Create an E3DB client object. */
E3DB_Client *E3DB_Client_New(E3DB_ClientOptions *opts)
{
	E3DB_Client *client = xmalloc(sizeof(E3DB_Client));
	client->options = opts;
	client->access_token = NULL;
	return client;
}

/* Free an E3DB client object. */
void E3DB_Client_Delete(E3DB_Client *client)
{
	E3DB_ClientOptions_Delete(client->options);
	if (client->access_token)
	{
		sdsfree(client->access_token);
	}
	xfree(client);
}

/*
 * {WriteRecord}
 *
 */

void WriteRecord(E3DB_Record_Legacy *record, E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta)
{
	// Write Record
}

/*
 * {ReadRecords}
 *
 */
void ReadRecords(E3DB_Record_Legacy **records, E3DB_Client *client, const char **all_record_ids)
{
	// Read Record
}
