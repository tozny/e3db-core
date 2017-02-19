/*
 * e3db_core.c
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "asprintf.h"
#include "cJSON.h"
#include "utlist.h"

#include "e3db_core.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

/*
 * {Client Options}
 */

#define DEFAULT_API_URL    "https://api.e3db.tozny.com/v1"
#define DEFAULT_API_KEY    ""
#define DEFAULT_API_SECRET ""

struct _E3DB_ClientOptions {
  char *api_url;
  char *api_key;
  char *api_secret;
  // TODO: Add other forms of authentication.
};

E3DB_ClientOptions *E3DB_ClientOptions_New(void)
{
  E3DB_ClientOptions *opts = xmalloc(sizeof(E3DB_ClientOptions));

  opts->api_url    = xstrdup(DEFAULT_API_URL);
  opts->api_key    = xstrdup(DEFAULT_API_KEY);
  opts->api_secret = xstrdup(DEFAULT_API_SECRET);

  return opts;
}

void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts)
{
  xfree(opts->api_url);
  xfree(opts->api_key);
  xfree(opts->api_secret);
  xfree(opts);
}

void E3DB_ClientOptions_SetApiUrl(E3DB_ClientOptions *opts, const char *url)
{
  xfree(opts->api_url);
  opts->api_url = xstrdup(url);
}

void E3DB_ClientOptions_SetApiKey(E3DB_ClientOptions *opts, const char *api_key)
{
  xfree(opts->api_key);
  opts->api_key = xstrdup(api_key);
}

void E3DB_ClientOptions_SetApiSecret(E3DB_ClientOptions *opts, const char *api_secret)
{
  xfree(opts->api_secret);
  opts->api_secret = xstrdup(api_secret);
}

/*
 * {Clients}
 */

struct _E3DB_Client {
  E3DB_ClientOptions *options;
  // TODO: Add cached JWT from auth service.
  // TODO: If we add mutable state (like the JWT above), also add a lock
  // so that concurrent access via multiple operations in flight is safe.
};

/* Create an E3DB client object. */
E3DB_Client *E3DB_Client_New(E3DB_ClientOptions *opts)
{
  E3DB_Client *client = xmalloc(sizeof(E3DB_Client));
  client->options = opts;
  return client;
}

/* Free an E3DB client object. */
void E3DB_Client_Delete(E3DB_Client *client)
{
  E3DB_ClientOptions_Delete(client->options);
  xfree(client);
}

/*
 * {Operations and Events}
 */

typedef enum {
  E3DB_OP_LIST_RECORDS,
} E3DB_OpType;

typedef enum {
  E3DB_OP_STATE_DONE,
  E3DB_OP_STATE_HTTP,
  E3DB_OP_STATE_CONFIG,
  E3DB_OP_STATE_KEY,
} E3DB_OpState;

struct _E3DB_Op {
  E3DB_OpType type;
  E3DB_OpState state;

  /* Information for the caller about the current state. */
  union {
    struct {
      char *method;
      char *url;
      char *body;
      E3DB_HttpHeaderList *headers;
      int (*next_state)(E3DB_Op *op, int response_code, const char *body,
                        E3DB_HttpHeaderList *headers, size_t num_headers);
    } http;

    struct {
      int dummy;
    } config;

    struct {
      char *writer_id;
    } key;
  } request;

  /* A pointer to the API-call specific result structure. */
  void *result;

  /* Deallocation function that frees `result'. */
  void (*free_result)(void *result);
};

/* Create a new operation of a specific type. */
static E3DB_Op *E3DB_Op_New(E3DB_OpType type)
{
  E3DB_Op *op = xmalloc(sizeof(E3DB_Op));
  op->type = type;
  op->state = E3DB_OP_STATE_DONE;
  return op;
}

/* Finish the current operation, freeing all internal state and
 * setting the `state' field to "done". The caller is free to
 * transition into a different non-done state after this call.
 *
 * It is important to note that this does not free `op'. Use
 * `E3DB_OpDelete' to both finish and delete the operation. */
static void E3DB_Op_Finish(E3DB_Op *op)
{
  switch (op->state) {
    case E3DB_OP_STATE_HTTP:
      xfree(op->request.http.url);
      xfree(op->request.http.body);
      xfree(op->request.http.method);
      E3DB_HttpHeaderList_Delete(op->request.http.headers);
      break;
    case E3DB_OP_STATE_KEY:
      xfree(op->request.key.writer_id);
      break;
    case E3DB_OP_STATE_CONFIG:
      break;
    case E3DB_OP_STATE_DONE:
      break;
  }

  op->state = E3DB_OP_STATE_DONE;
}

void E3DB_Op_Delete(E3DB_Op *op)
{
  if (op->free_result) {
    op->free_result(op->result);
  }

  E3DB_Op_Finish(op);
  xfree(op);
}

int E3DB_Op_IsDone(E3DB_Op *op)
{
  return (op->state == E3DB_OP_STATE_DONE);
}

/*
 * {HTTP Headers}
 */

typedef struct _E3DB_HttpHeader E3DB_HttpHeader;

struct _E3DB_HttpHeader {
  char *value;
  E3DB_HttpHeader *next;
};

struct _E3DB_HttpHeaderList {
  E3DB_HttpHeader *header_list;
};

/* Create a new empty set of HTTP headers. */
E3DB_HttpHeaderList *E3DB_HttpHeaderList_New(void)
{
  E3DB_HttpHeaderList *headers = xmalloc(sizeof(E3DB_HttpHeaderList));
  headers->header_list = NULL;
  return headers;
}

/* Delete a set of HTTP headers. */
void E3DB_HttpHeaderList_Delete(E3DB_HttpHeaderList *hdrs)
{
  E3DB_HttpHeader *hdr, *tmp;

  LL_FOREACH_SAFE(hdrs->header_list, hdr, tmp) {
    LL_DELETE(hdrs->header_list, hdr);
    xfree(hdr->value);
    xfree(hdr);
  }

  xfree(hdrs);
}

/* Add a header to a set of HTTP headers. */
void E3DB_HttpHeaderList_Add(E3DB_HttpHeaderList *hdrs, const char *header)
{
  E3DB_HttpHeader *hdr = xmalloc(sizeof(E3DB_HttpHeader));
  hdr->value = xstrdup(header);
  LL_PREPEND(hdrs->header_list, hdr);
}

/* Return the number of headers in a set. */
size_t E3DB_HttpHeaderList_GetLength(E3DB_HttpHeaderList *hdrs)
{
  E3DB_HttpHeader *hdr;
  size_t result = 0;
  LL_COUNT(hdrs->header_list, hdr, result);
  return result;
}

/* Return the first header in a set or NULL if the set is empty. */
E3DB_HttpHeader *E3DB_HttpHeaderList_GetFirst(E3DB_HttpHeaderList *hdrs)
{
  assert(hdrs != NULL);
  return hdrs->header_list;
}

/* Return the next header in a set, or NULL if this is the last one. */
E3DB_HttpHeader *E3DB_HttpHeader_GetNext(E3DB_HttpHeader *header)
{
  assert(header != NULL);
  return header->next;
}

/* Return the string value of an HTTP header. */
const char *E3DB_HttpHeader_GetValue(E3DB_HttpHeader *header)
{
  assert(header != NULL);
  return header->value;
}

/*
 * {HTTP State}
 */

int E3DB_Op_IsHttpState(E3DB_Op *op)
{
  return (op->state == E3DB_OP_STATE_HTTP);
}

const char *E3DB_Op_GetHttpMethod(E3DB_Op *op)
{
  assert(op->state == E3DB_OP_STATE_HTTP);
  return op->request.http.method;
}

const char *E3DB_Op_GetHttpUrl(E3DB_Op *op)
{
  assert(op->state == E3DB_OP_STATE_HTTP);
  return op->request.http.url;
}

E3DB_HttpHeaderList *E3DB_Op_GetHttpHeaders(E3DB_Op *op)
{
  assert(op->state == E3DB_OP_STATE_HTTP);
  return op->request.http.headers;
}

const char *E3DB_Op_GetHttpBody(E3DB_Op *op)
{
  assert(op->state == E3DB_OP_STATE_HTTP);
  return op->request.http.body;
}

int E3DB_Op_FinishHttpState(E3DB_Op *op, int response_code, const char *body,
                         E3DB_HttpHeaderList *headers, size_t num_headers)
{
  assert(op->state == E3DB_OP_STATE_HTTP);
  return (*op->request.http.next_state)(op, response_code, body, headers,
                                        num_headers);
}

/*
 * {Records and Metadata}
 */

struct _E3DB_RecordMeta {
  char *record_id;
  char *writer_id;
  char *user_id;
  char *type;
  // TODO: Add creation/modification time.
  // TODO: Support custom plaintext metadata.
};

const char *E3DB_RecordMeta_GetRecordId(E3DB_RecordMeta *meta)
{
  return meta->record_id;
}

const char *E3DB_RecordMeta_GetWriterId(E3DB_RecordMeta *meta)
{
  return meta->writer_id;
}

const char *E3DB_RecordMeta_GetUserId(E3DB_RecordMeta *meta)
{
  return meta->user_id;
}

const char *E3DB_RecordMeta_GetType(E3DB_RecordMeta *meta)
{
  return meta->type;
}

/* Utility function to safely get the string value of a JSON object field,
 * returning an empty string if not present. */
static char *cJSON_GetSafeObjectItemString(cJSON *json, const char *name)
{
  cJSON *obj = cJSON_GetObjectItem(json, name);

  if (obj == NULL || obj->type != cJSON_String) {
    fprintf(stderr, "Warning: Field '%s' missing or not a string.\n", name);
    return "";
  } else {
    return obj->valuestring;
  }
}

/*
 * {API Calls}
 */

typedef struct _E3DB_ListRecordsResult {
  cJSON *json;
} E3DB_ListRecordsResult;

typedef struct _E3DB_ListRecordsResultIterator {
  cJSON *pos;               // never needs freeing
  E3DB_RecordMeta meta;     // reused to avoid allocations on iteration
} E3DB_ListRecordsResultIterator;

static void E3DB_ListRecordsResult_Delete(void *p)
{
  E3DB_ListRecordsResult *result = p;

  if (result != NULL) {
    if (result->json != NULL) {
      cJSON_Delete(result->json);
    }
    free(result);
  }
}

static int E3DB_ListRecords_Response(E3DB_Op *op, int response_code,
                                    const char *body, E3DB_HttpHeaderList *headers,
                                    size_t num_headers)
{
  if (response_code != 200) {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  cJSON *json = cJSON_Parse(body);

  if (json == NULL) {
    // TODO: Figure out proper error handling here.
    fprintf(stderr, "Fatal: Parsing ListRecords JSON failed.\n");
    abort();
  }

  E3DB_ListRecordsResult *result = op->result;
  result->json = json;

  E3DB_Op_Finish(op);
  return 0;
}

// TODO: Split this out into its own file.
E3DB_Op *E3DB_ListRecords_Begin(E3DB_Client *client, int limit, int offset,
                                UUID *writer_id, const char *types[],
                                size_t num_types)
{
  E3DB_Op *op = E3DB_Op_New(E3DB_OP_LIST_RECORDS);

  // TODO: Handle the `writer_id' and `types' parameters.
  op->state = E3DB_OP_STATE_HTTP;
  asprintf(&(op->request.http.url), "%s/records?limit=%d&offset=%d",
           client->options->api_url, limit, offset);

  op->request.http.method = xstrdup("GET");
  op->request.http.body = xstrdup("");

  // TODO: Use the auth service once it is ready for prime time.
  char *credentials, *credentials_base64, *auth_header;
  asprintf(&credentials, "%s:%s", client->options->api_key, client->options->api_secret);
  credentials_base64 = base64_encode(credentials);
  asprintf(&auth_header, "Authorization: Basic %s", credentials_base64);

  op->request.http.headers = E3DB_HttpHeaderList_New();
  E3DB_HttpHeaderList_Add(op->request.http.headers, auth_header);
  op->request.http.next_state = E3DB_ListRecords_Response;

  op->result = xmalloc(sizeof(E3DB_ListRecordsResult));
  op->free_result = E3DB_ListRecordsResult_Delete;

  xfree(auth_header);
  xfree(credentials_base64);
  xfree(credentials);

  return op;
}

E3DB_ListRecordsResult *E3DB_ListRecords_GetResult(E3DB_Op *op)
{
  return op->result;
}

E3DB_ListRecordsResultIterator *E3DB_ListRecordsResult_GetIterator(E3DB_ListRecordsResult *result)
{
  E3DB_ListRecordsResultIterator *it = xmalloc(sizeof(*it));
  it->pos = result->json->child;
  return it;
}

void E3DB_ListRecordsResultIterator_Delete(E3DB_ListRecordsResultIterator *it)
{
  xfree(it);
}

int E3DB_ListRecordsResultIterator_IsDone(E3DB_ListRecordsResultIterator *it)
{
  return (it->pos == NULL);
}

void E3DB_ListRecordsResultIterator_Next(E3DB_ListRecordsResultIterator *it)
{
  assert(it->pos);
  it->pos = it->pos->next;
}

E3DB_RecordMeta *E3DB_ListRecordsResultIterator_Get(E3DB_ListRecordsResultIterator *it)
{
  it->meta.record_id = cJSON_GetSafeObjectItemString(it->pos, "record_id");
  it->meta.writer_id = cJSON_GetSafeObjectItemString(it->pos, "writer_id");
  it->meta.user_id   = cJSON_GetSafeObjectItemString(it->pos, "user_id");
  it->meta.type      = cJSON_GetSafeObjectItemString(it->pos, "type");

  return &it->meta;
}
