/*
 * e3db_core.h
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#ifndef E3DB_CORE_H_INCLUDED
#define E3DB_CORE_H_INCLUDED

/*
 * {Client Options}
 */

typedef struct _E3DB_ClientOptions E3DB_ClientOptions;

E3DB_ClientOptions *E3DB_ClientOptions_New(void);
void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts);

void E3DB_ClientOptions_SetApiUrl(E3DB_ClientOptions *opts, const char *url);
void E3DB_ClientOptions_SetApiKey(E3DB_ClientOptions *opts, const char *api_key);
void E3DB_ClientOptions_SetApiSecret(E3DB_ClientOptions *opts, const char *api_secret);

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
void E3DB_HttpHeaderList_Add(E3DB_HttpHeaderList *hdrs, const char *header);

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

/*
 * {List Records}
 */

typedef struct _E3DB_ListRecordsResult E3DB_ListRecordsResult;
typedef struct _E3DB_ListRecordsResultIterator E3DB_ListRecordsResultIterator;

E3DB_Op *E3DB_ListRecords_Begin(E3DB_Client *client, int limit, int offset,
                                UUID *writer_id, const char *types[],
                                size_t num_types);

/* has same lifetime as operation, doesn't need freeing */
E3DB_ListRecordsResult *E3DB_ListRecords_GetResult(E3DB_Op *op);

E3DB_ListRecordsResultIterator *E3DB_ListRecordsResult_GetIterator(E3DB_ListRecordsResult *result);
void E3DB_ListRecordsResultIterator_Delete(E3DB_ListRecordsResultIterator *it);

int E3DB_ListRecordsResultIterator_IsDone(E3DB_ListRecordsResultIterator *it);
void E3DB_ListRecordsResultIterator_Next(E3DB_ListRecordsResultIterator *it);
E3DB_RecordMeta *E3DB_ListRecordsResultIterator_Get(E3DB_ListRecordsResultIterator *it);

#endif   /* !defined E3DB_CORE_H_INCLUDED */
