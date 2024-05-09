/*
 * e3db_client.h
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#ifndef E3DB_ClIENT_H_INCLUDED
#define E3DB_ClIENT_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h> // for size_t
#include "cJSON.h"
#include "e3db_core.h"

	/*
	 * {ReadRecords}
	 *
	 */
	E3DB_Record *ReadRecords(E3DB_Client *client, const char **all_record_ids, int argumentCount);

	/*
	 * {WriteRecord}
	 *
	 */

	E3DB_Record *WriteRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta);

	/*
	 * {EncryptRecord}
	 *
	 */
	E3DB_LocalRecord *EncryptRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta, unsigned char *accesskey);

	/*
	 * {FetchRecordAccessKey}
	 *
	 */
	unsigned char *FetchRecordAccessKey(E3DB_Client *client, char *record_type);

	/*
	 * {DecryptRecord}
	 *
	 */
	E3DB_LocalRecord *DecryptRecord(E3DB_Client *client, const char **record_type, cJSON *data, cJSON *meta, unsigned char *accesskey);

#ifdef __cplusplus
}
#endif

#endif /* !defined E3DB_ClIENT_H_INCLUDED */
