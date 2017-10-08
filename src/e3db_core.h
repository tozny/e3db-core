/*
 * e3db_core.h
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#ifndef E3DB_CORE_H_INCLUDED
#define E3DB_CORE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>          // for size_t

// TODO: Add error handling machinery to this library.

/*
 * {Client Options}
 */

typedef struct _E3DB_ClientOptions E3DB_ClientOptions;

E3DB_ClientOptions *E3DB_ClientOptions_New(void);
void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts);

void E3DB_ClientOptions_SetApiUrl(E3DB_ClientOptions *opts, const char *url);
void E3DB_ClientOptions_SetApiKey(E3DB_ClientOptions *opts, const char *api_key);
void E3DB_ClientOptions_SetApiSecret(E3DB_ClientOptions *opts, const char *api_secret);
void E3DB_ClientOptions_SetClientId(E3DB_ClientOptions *opts, const char *client_id);
void E3DB_ClientOptions_SetPublicKey(E3DB_ClientOptions *opts, const char *public_key);
void E3DB_ClientOptions_SetPrivateKey(E3DB_ClientOptions *opts, const char *private_key);

// TODO: Other ways to authenticate---Tozny, OIDC, etc.

/*
 * {Clients}
 */

typedef struct _E3DB_Client E3DB_Client;

/* Create an E3DB client object given a set of options.  The newly created
 * client assumes ownership of `opts', so it does not need to be freed. */
E3DB_Client *E3DB_Client_New(E3DB_ClientOptions *opts);

/* Free an E3DB client object. */
void E3DB_Client_Delete(E3DB_Client *client);

/*
 * {HTTP Headers}
 *
 * When performing API requests, the state machine will pass along a set of
 * headers that should be included in the request. The `E3DB_HttpHeaderList`
 * interface is used to manage that list of header values.
 */

/* A set of HTTP header values. */
typedef struct _E3DB_HttpHeaderList E3DB_HttpHeaderList;

/* A single HTTP header value. */
typedef struct _E3DB_HttpHeader E3DB_HttpHeader;

/* Create a new empty set of HTTP headers.  This must be freed with
 * `E3DB_HttpHeaderList_Delete' when it is no longer needed. */
E3DB_HttpHeaderList *E3DB_HttpHeaderList_New(void);

/* Delete a set of HTTP headers. */
void E3DB_HttpHeaderList_Delete(E3DB_HttpHeaderList *hdrs);

/* Add a header to a set of HTTP headers.  The header list will own a copy
 * of the string in `header'. */
void E3DB_HttpHeaderList_Add(E3DB_HttpHeaderList *hdrs, const char *name, const char *value);

/* Return the number of headers in a set. */
size_t E3DB_HttpHeaderList_GetLength(E3DB_HttpHeaderList *hdrs);

/* Return the first header in a set or NULL if the set is empty.  The
 * returned header has a lifetime of the containing header list and
 * should not be freed by the caller. */
E3DB_HttpHeader *E3DB_HttpHeaderList_GetFirst(E3DB_HttpHeaderList *hdrs);
// TODO: Maybe this should return a "void *" iterator that you can call
// `GetNext' and `GetValue' on, rather than a header directly?

/* Return the next header in a set, or NULL if this is the last one.  The
 * returned header has a lifetime of the containing header list and
 * should not be freed by the caller. */
E3DB_HttpHeader *E3DB_HttpHeader_GetNext(E3DB_HttpHeader *header);

/* Return the string name of an HTTP header. */
const char *E3DB_HttpHeader_GetName(E3DB_HttpHeader *header);

/* Return the string value of an HTTP header.  The returned string
 * has a lifetime of the containing header and should not be freed
 * by the caller. */
const char *E3DB_HttpHeader_GetValue(E3DB_HttpHeader *header);

/*
 * {Operations}
 */

typedef int UUID;   // XXX temporary

typedef struct _E3DB_Op E3DB_Op;

/* Return true if an operation has completed. */
int E3DB_Op_IsDone(E3DB_Op *op);

/* Clean up all resources associated with `op' regardless of state. */
void E3DB_Op_Delete(E3DB_Op *op);

/* Return true if `op' is in an HTTP request state. */
int E3DB_Op_IsHttpState(E3DB_Op *op);

const char *E3DB_Op_GetHttpMethod(E3DB_Op *op);
const char *E3DB_Op_GetHttpUrl(E3DB_Op *op);
E3DB_HttpHeaderList *E3DB_Op_GetHttpHeaders(E3DB_Op *op);
const char *E3DB_Op_GetHttpBody(E3DB_Op *op);
int E3DB_Op_FinishHttpState(E3DB_Op *op, int response_code, const char *body,
                            E3DB_HttpHeaderList *headers, size_t num_headers);

/* Return true if `op` is in a client configuration state. */
int E3DB_Op_IsConfigState(E3DB_Op *op);

/* Return true if `op' is in a client key information state. */
int E3DB_Op_IsKeyState(E3DB_Op *op);

int E3DB_Op_GetKeyWriterId(E3DB_Op *op);
int E3DB_Op_FinishKeyState(E3DB_Op *op, ...);

/*
 * {Record Data and Metadata}
 */

typedef struct _E3DB_RecordMeta E3DB_RecordMeta;

// TODO: Create and delete record meta objects.
// TODO: Setters

const char *E3DB_RecordMeta_GetRecordId(E3DB_RecordMeta *meta);
const char *E3DB_RecordMeta_GetWriterId(E3DB_RecordMeta *meta);
const char *E3DB_RecordMeta_GetUserId(E3DB_RecordMeta *meta);
const char *E3DB_RecordMeta_GetType(E3DB_RecordMeta *meta);
// TODO: creation and modification time

typedef struct _E3DB_Record E3DB_Record;
typedef struct _E3DB_RecordFieldIterator E3DB_RecordFieldIterator;

// TODO: Create and delete record objects
// TODO: Setters
// TODO: Consider an adaptor to JSON?

/* Return the value of a field in a record. Returns NULL if the field
 * doesn't exist. The returned string lasts until the containing
 * record is deleted. */
const char *E3DB_Record_GetField(E3DB_Record *r, const char *field);

/* Return an iterator over the fields of a record. */
E3DB_RecordFieldIterator *E3DB_Record_GetFieldIterator(E3DB_Record *r);

/* Delete a record field iterator. */
void E3DB_RecordFieldIterator_Delete(E3DB_RecordFieldIterator *it);

/* Returns true if a record field iterator is completed. */
int E3DB_RecordFieldIterator_IsDone(E3DB_RecordFieldIterator *it);

/* Move a record field iterator to the next value. */
void E3DB_RecordFieldIterator_Next(E3DB_RecordFieldIterator *it);

/* Return the name of the current field an iterator is pointing to. */
const char *E3DB_RecordFieldIterator_GetName(E3DB_RecordFieldIterator *it);

/* Return the value of the current field an iterator is pointing to. */
const char *E3DB_RecordFieldIterator_GetValue(E3DB_RecordFieldIterator *it);

/*
 * {Query}
 *
 * We use a single "query" interface for both listing and reading
 * records.
 */

typedef struct _E3DB_QueryResult E3DB_QueryResult;
typedef struct _E3DB_QueryResultIterator E3DB_QueryResultIterator;

typedef struct {
  const char  **writer_ids;
  size_t      num_writer_ids;

  const char  **record_ids;
  size_t      num_record_ids;

  const char  **types;
  size_t      num_types;

  int         include_data;
  int         include_all_writers;
  int         page_size;
  int         after_index;
  int         raw;
} E3DB_QueryOptions;

/* Initialize a query options structure with default values (contains
 * data, page size of 50 starting the beginning, all writers, records,
 * and types). */
void E3DB_QueryOptions_SetDefault(E3DB_QueryOptions *options);

/* Begin a query operation given a set of options. */
E3DB_Op *E3DB_Query_Begin(E3DB_Client *client, E3DB_QueryOptions *options);

/* Return the result of a successful query operation. Returns NULL if
 * the operation is not yet complete. The returned structure has the
 * same lifetime as the containing operation and does not need to be freed. */
E3DB_QueryResult *E3DB_Query_GetResult(E3DB_Op *op);

/* Return the number of results from a completed query operation. If
 * this returns zero, then a paginated operation has completed. */
int E3DB_QueryResult_GetCount(E3DB_QueryResult *result);

/* Return the last index reported by the server for a result set. This
 * is used during pagination and passed as "after_index" for the next
 * search operation. */
int E3DB_QueryResult_GetLastIndex(E3DB_QueryResult *result);

/* Return an iterator to the set of record metadata (and optionally data)
 * returned from a query result set. This must be freed with
 * "E3DB_QueryResultIterator_Delete". */
E3DB_QueryResultIterator *E3DB_QueryResult_GetIterator(E3DB_QueryResult *result);

/* Delete a query result iterator. */
void E3DB_QueryResultIterator_Delete(E3DB_QueryResultIterator *it);

/* Returns true if a query result iterator is completed. */
int E3DB_QueryResultIterator_IsDone(E3DB_QueryResultIterator *it);

/* Move a query result iterator to the next value. */
void E3DB_QueryResultIterator_Next(E3DB_QueryResultIterator *it);

/* Return the metadata for the current record in the result set. */
E3DB_RecordMeta *E3DB_QueryResultIterator_GetMeta(E3DB_QueryResultIterator *it);

/* Return the record data for the current record in the result set. */
E3DB_Record *E3DB_QueryResultIterator_GetData(E3DB_QueryResultIterator *it);

#ifdef __cplusplus
}
#endif

#endif   /* !defined E3DB_CORE_H_INCLUDED */
