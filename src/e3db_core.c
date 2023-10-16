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

#include "cJSON.h"
#include "utlist.h"
#include "sds.h"

#include "e3db_core.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

#include "sodium.h"

/*
 * {Client Options}
 */

#define DEFAULT_API_URL "https://api.e3db.com"
#define DEFAULT_AUTH_URL "https://api.e3db.com/v1/auth"
#define DEFAULT_API_KEY ""
#define DEFAULT_API_SECRET ""
#define DEFAULT_CLIENT_ID ""
#define SECRET_KEY_SIZE 32

struct _E3DB_ClientOptions
{
  sds api_url;
  sds api_key;
  sds api_secret;
  sds client_id;
  sds private_key;
  sds public_key;
  sds private_signing_key;
  // TODO: Add other forms of authentication.
};

E3DB_ClientOptions *E3DB_ClientOptions_New(void)
{
  E3DB_ClientOptions *opts = xmalloc(sizeof(E3DB_ClientOptions));

  opts->api_url = sdsnew(DEFAULT_API_URL);
  opts->api_key = sdsnew(DEFAULT_API_KEY);
  opts->api_secret = sdsnew(DEFAULT_API_SECRET);
  opts->client_id = sdsnew(DEFAULT_CLIENT_ID);

  return opts;
}

void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts)
{
  sdsfree(opts->api_url);
  sdsfree(opts->api_key);
  sdsfree(opts->api_secret);
  sdsfree(opts->client_id);
  sdsfree(opts->private_key);
  sdsfree(opts->public_key);
  sdsfree(opts->private_signing_key);
  xfree(opts);
}

void E3DB_ClientOptions_SetApiUrl(E3DB_ClientOptions *opts, const char *url)
{
  sdsfree(opts->api_url);
  opts->api_url = sdsnew(url);
}

void E3DB_ClientOptions_SetApiKey(E3DB_ClientOptions *opts, const char *api_key)
{
  sdsfree(opts->api_key);
  opts->api_key = sdsnew(api_key);
}

void E3DB_ClientOptions_SetApiSecret(E3DB_ClientOptions *opts, const char *api_secret)
{
  sdsfree(opts->api_secret);
  opts->api_secret = sdsnew(api_secret);
}
void E3DB_ClientOptions_SetClientID(E3DB_ClientOptions *opts, const char *client_id)
{
  sdsfree(opts->client_id);
  opts->client_id = sdsnew(client_id);
}
void E3DB_ClientOptions_SetPrivateKey(E3DB_ClientOptions *opts, const char *private_key)
{
  sdsfree(opts->private_key);
  opts->private_key = sdsnew(private_key);
}
void E3DB_ClientOptions_SetPublicKey(E3DB_ClientOptions *opts, const char *public_key)
{
  sdsfree(opts->public_key);
  opts->public_key = sdsnew(public_key);
}
void E3DB_ClientOptions_SetPrivateSigningKey(E3DB_ClientOptions *opts, const char *private_signing_key)
{
  sdsfree(opts->private_signing_key);
  opts->private_signing_key = sdsnew(private_signing_key);
}
/*
 * {Clients}
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
 * {Operations and Events}
 */

typedef enum
{
  E3DB_OP_LIST_RECORDS,
  E3DB_OP_READ_RECORDS,
  E3DB_OP_ENCRYPTED_ACCESS_KEYS,
  E3DB_OP_WRITE_RECORD,
  E3DB_OP_CREATE_ACCESS_KEYS,
} E3DB_OpType;

typedef enum
{
  E3DB_OP_STATE_DONE,
  E3DB_OP_STATE_HTTP,
  E3DB_OP_STATE_CONFIG,
  E3DB_OP_STATE_KEY,
} E3DB_OpState;

typedef int (*E3DB_Op_HttpNextStateFn)(E3DB_Op *op, int response_code,
                                       const char *body, E3DB_HttpHeaderList *headers, size_t num_headers);

struct _E3DB_Op
{
  E3DB_Client *client;
  E3DB_OpType type;
  E3DB_OpState state;

  /* Information for the caller about the current state. */
  union
  {
    struct
    {
      sds method;
      sds url;
      sds body;
      E3DB_HttpHeaderList *headers;
      E3DB_Op_HttpNextStateFn next_state;
    } http;

    struct
    {
      int dummy;
    } config;

    struct
    {
      char *writer_id;
    } key;
  } request;

  /* A pointer to the API-call specific result structure. */
  void *result;

  /* Deallocation function that frees `result'. */
  void (*free_result)(void *result);
};

/* Create a new operation of a specific type. */
static E3DB_Op *E3DB_Op_New(E3DB_Client *client, E3DB_OpType type)
{
  E3DB_Op *op = xmalloc(sizeof(E3DB_Op));
  op->client = client;
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
  switch (op->state)
  {
  case E3DB_OP_STATE_HTTP:
    sdsfree(op->request.http.url);
    sdsfree(op->request.http.body);
    sdsfree(op->request.http.method);
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
  if (op->free_result)
  {
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

struct _E3DB_HttpHeader
{
  char *name;
  char *value;
  E3DB_HttpHeader *next;
};

struct _E3DB_HttpHeaderList
{
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

  LL_FOREACH_SAFE(hdrs->header_list, hdr, tmp)
  {
    LL_DELETE(hdrs->header_list, hdr);
    sdsfree(hdr->name);
    sdsfree(hdr->value);
    xfree(hdr);
  }

  xfree(hdrs);
}

/* Add a header to a set of HTTP headers. */
void E3DB_HttpHeaderList_Add(E3DB_HttpHeaderList *hdrs, const char *name, const char *value)
{
  E3DB_HttpHeader *hdr = xmalloc(sizeof(E3DB_HttpHeader));
  hdr->name = sdsnew(name);
  hdr->value = sdsnew(value);
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

/* Return the string name of an HTTP header. */
const char *E3DB_HttpHeader_GetName(E3DB_HttpHeader *header)
{
  assert(header != NULL);
  return header->name;
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
  return (*op->request.http.next_state)(op, response_code, body, headers, num_headers);
}

/*
 * {Records and Metadata}
 */

struct _E3DB_RecordMeta
{
  char *record_id;
  char *writer_id;
  char *user_id;
  char *type;
  char *version;
  char *created;
  char *last_modified;
  cJSON *plain;
  // TODO: Add creation/modification time.
  // TODO: Support custom plaintext metadata.
};

struct _E3DB_DecryptedRecord
{
  E3DB_RecordMeta *meta;
  cJSON *data;
  char *rec_sig;
};

/*
 * Authorizer signing key
 */

struct _E3DB_SignerSigningKey
{
  char *ed25519;
};

/*
 * Authorizer public key
 */

struct _E3DB_AuthPubKey
{
  char *curve25519;
};

/*
 * Encrypted access key
 */

struct _E3DB_EAK
{
  char *eak;
  char *signer_id;
  char *authorizer_id;
  E3DB_SignerSigningKey signer_signing_key;
  E3DB_AuthPubKey auth_pub_key;
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

const char *E3DB_RecordMeta_GetPlain(E3DB_RecordMeta *meta)
{
  return meta->plain;
}

const char *E3DB_EAK_GetEAK(E3DB_EAK *eak)
{
  return eak->eak;
}

const char *E3DB_EAK_GetAuthPubKey(E3DB_EAK *eak)
{
  return eak->auth_pub_key.curve25519;
}

/* Utility function to safely get the string value of a JSON object field,
 * returning an empty string if not present. */
static char *cJSON_GetSafeObjectItemString(cJSON *json, const char *name)
{
  cJSON *obj = cJSON_GetObjectItem(json, name);

  if (obj == NULL || obj->type != cJSON_String)
  {
    fprintf(stderr, "Warning: Field '%s' missing or not a string.\n", name);
    return "";
  }
  else
  {
    return obj->valuestring;
  }
}

/* Utility function to safely get the string value of a JSON object field,
 * returning an empty string if not present. */
static char *cJSON_GetSafeObjectItem(cJSON *json, const char *name)
{
  cJSON *obj = cJSON_GetObjectItem(json, name);
  printf("\ncJSON_GetSafeObjectItem name = %s\n", name);

  if (obj == NULL)
  {
    fprintf(stderr, "Warning: Field '%s' missing or not a string.\n", name);
    return "";
  }
  if (obj->type == cJSON_String)
  {
    char *plain = obj->valuestring;
    printf("\ncJSON_GetSafeObjectItem plain = %s\n", plain);
    return plain;
  }
}

static void E3DB_GetRecordMetaFromJSON(cJSON *json, E3DB_RecordMeta *meta)
{
  meta->record_id = cJSON_GetSafeObjectItemString(json, "record_id");
  meta->writer_id = cJSON_GetSafeObjectItemString(json, "writer_id");
  meta->user_id = cJSON_GetSafeObjectItemString(json, "user_id");
  meta->type = cJSON_GetSafeObjectItemString(json, "type");
  meta->plain = cJSON_GetObjectItem(json, "plain");
  meta->version = cJSON_GetSafeObjectItemString(json, "version");
  meta->created = cJSON_GetSafeObjectItemString(json, "created");
  meta->last_modified = cJSON_GetSafeObjectItemString(json, "last_modified");
  printf("\nE3DB_GetRecordMetaFromJSON plain %s\n", meta->plain);
}

static void E3DB_GetSignerSigningKeyFromJSON(cJSON *json, E3DB_SignerSigningKey *signer_signing_key)
{
  signer_signing_key->ed25519 = cJSON_GetSafeObjectItemString(json, "ed25519");
}

static void E3DB_GetAuthPubKeyFromJSON(cJSON *json, E3DB_AuthPubKey *auth_pub_key)
{
  auth_pub_key->curve25519 = cJSON_GetSafeObjectItemString(json, "curve25519");
}

// TODO: How to reconcile this with decryption?
struct _E3DB_Record
{
  cJSON *json; // "data" field within record
};

struct _E3DB_RecordFieldIterator
{
  cJSON *pos;
};

/* Return the value of a field in a record. Returns NULL if the field
 * doesn't exist. The returned string lasts until the containing
 * record is deleted. */
const char *E3DB_Record_GetField(E3DB_Record *r, const char *field)
{
  assert(r != NULL);
  assert(r->json != NULL);

  cJSON *j = cJSON_GetObjectItem(r->json, field);
  if (j == NULL)
  {
    fprintf(stderr, "Error: Field '%s' doesn't exist.\n", field);
    return NULL;
  }

  if (j->type != cJSON_String)
  {
    fprintf(stderr, "Error: Field '%s' has unexpected type.\n", field);
    return NULL;
  }

  return j->valuestring;
}

/* Return an iterator over the fields of a record. */
E3DB_RecordFieldIterator *E3DB_Record_GetFieldIterator(E3DB_Record *r)
{
  assert(r != NULL);
  assert(r->json != NULL);

  E3DB_RecordFieldIterator *it = xmalloc(sizeof(*it));
  it->pos = r->json->child;
  return it;
}

/* Delete a record field iterator. */
void E3DB_RecordFieldIterator_Delete(E3DB_RecordFieldIterator *it)
{
  xfree(it);
}

/* Returns true if a record field iterator is completed. */
int E3DB_RecordFieldIterator_IsDone(E3DB_RecordFieldIterator *it)
{
  assert(it != NULL);
  return (it->pos == NULL);
}

/* Move a record field iterator to the next value. */
void E3DB_RecordFieldIterator_Next(E3DB_RecordFieldIterator *it)
{
  assert(it != NULL);
  assert(it->pos != NULL);
  it->pos = it->pos->next;
}

/* Return the name of the current field an iterator is pointing to. */
const char *E3DB_RecordFieldIterator_GetName(E3DB_RecordFieldIterator *it)
{
  assert(it != NULL);
  assert(it->pos != NULL);
  return it->pos->string;
}

/* Return the value of the current field an iterator is pointing to. */
const char *E3DB_RecordFieldIterator_GetValue(E3DB_RecordFieldIterator *it)
{
  assert(it != NULL);
  assert(it->pos != NULL);
  return it->pos->valuestring;
}

/*
 * {API Calls}
 */

static sds E3DB_GetAuthHeader(E3DB_Client *client)
{
  sds credentials = sdscatprintf(sdsempty(), "%s:%s", client->options->api_key, client->options->api_secret);
  sds credentials_base64 = base64_encode(credentials);
  sds auth_header = sdsnew("Basic ");
  auth_header = sdscat(auth_header, credentials_base64);

  sdsfree(credentials_base64);
  sdsfree(credentials);

  return auth_header;
}

/* Handle an HTTP response with an OAuth access token. The token is stored
 * in the client and will be used to authenticate subsequent requests. */
static void E3DB_HandleAuthResponse(E3DB_Op *op, int response_code, const char *body)
{
  if (response_code != 200)
  {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  // TODO: Factor this all out into a helper function.
  // Parse the response body then extract and store the access token.
  cJSON *json = cJSON_Parse(body);

  if (json == NULL)
  {
    // TODO: Error handling.
    fprintf(stderr, "Fatal: Unable to parse JSON response.\n");
    abort();
  }

  sdsfree(op->client->access_token);
  op->client->access_token = sdsnew(cJSON_GetSafeObjectItemString(json, "access_token"));
  free(json);
  E3DB_Op_Finish(op);
}

/**
 * Initialize an E3DB operation to make a request to the authentication
 * service to obtain an access token.
 */
static void E3DB_InitAuthOp(E3DB_Client *client, E3DB_Op *op, E3DB_Op_HttpNextStateFn next_state)
{
  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = sdscatprintf(sdsempty(), "%s/token", DEFAULT_AUTH_URL);

  op->request.http.method = sdsnew("POST");
  op->request.http.body = sdsnew("grant_type=client_credentials");
  op->request.http.next_state = next_state;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = E3DB_GetAuthHeader(client);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Content-Type", "application/x-www-form-urlencoded");
  sdsfree(auth_header);
}

typedef struct _E3DB_ListRecordsResult
{
  cJSON *json;
  int limit;
  int offset;
} E3DB_ListRecordsResult;

typedef struct _E3DB_EncryptedAccessKeyResult
{
  cJSON *json; // entire ciphertext response body
  const char **writer_id;
  const char **user_id;
  const char **reader_id;
  const char **type;
} E3DB_EncryptedAccessKeyResult;

typedef struct _E3DB_CreateAccessKeyResult
{
  cJSON *json; // entire ciphertext response body
  const char **writer_id;
  const char **user_id;
  const char **reader_id;
  const char **type;
  const char **ak;
} E3DB_CreateAccessKeyResult;

typedef struct _E3DB_ListRecordsResultIterator
{
  cJSON *pos;           // never needs freeing
  E3DB_RecordMeta meta; // reused to avoid allocations on iteration
} E3DB_ListRecordsResultIterator;

typedef struct _E3DB_GetEAKResultIterator
{
  cJSON *pos; // never needs freeing
  E3DB_EAK EAK;

} E3DB_GetEAKResultIterator;

static void E3DB_ListRecordsResult_Delete(void *p)
{
  E3DB_ListRecordsResult *result = p;

  if (result != NULL)
  {
    if (result->json != NULL)
    {
      cJSON_Delete(result->json);
    }
    xfree(result);
  }
}

static void E3DB_EncryptedAccessKeyResult_Delete(void *p)
{
  E3DB_EncryptedAccessKeyResult *result = p;

  if (result != NULL)
  {
    if (result->json != NULL)
    {
      cJSON_Delete(result->json);
    }
    xfree(result);
  }
}

static int E3DB_ListRecords_Response(E3DB_Op *op, int response_code,
                                     const char *body, E3DB_HttpHeaderList *headers,
                                     size_t num_headers)
{
  if (response_code != 200)
  {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  cJSON *json = cJSON_Parse(body);

  if (json == NULL)
  {
    // TODO: Figure out proper error handling here.
    fprintf(stderr, "Fatal: Parsing ListRecords JSON failed.\n");
    abort();
  }

  E3DB_ListRecordsResult *result = op->result;
  result->json = json;

  E3DB_Op_Finish(op);

  return 0;
}

static void E3DB_ListRecords_InitOp(E3DB_Op *op)
{
  E3DB_ListRecordsResult *result = op->result;

  // TODO: Handle the `writer_id' and `types' parameters.
  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = sdscatprintf(sdsempty(), "%s/v1/storage/search",
                                      op->client->options->api_url);

  op->request.http.method = sdsnew("POST");
  op->request.http.body = sdsnew("");
  op->request.http.next_state = E3DB_ListRecords_Response;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = sdsnew("Bearer ");
  auth_header = sdscat(auth_header, op->client->access_token);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  sdsfree(auth_header);
}

static int E3DB_ListRecords_Request(E3DB_Op *op, int response_code,
                                    const char *body, E3DB_HttpHeaderList *headers,
                                    size_t num_headers)
{
  E3DB_HandleAuthResponse(op, response_code, body);
  E3DB_ListRecords_InitOp(op);
  return 0;
}

// TODO: Split this out into its own file.
E3DB_Op *E3DB_ListRecords_Begin(E3DB_Client *client, int limit, int offset,
                                UUID *writer_id, const char *types[],
                                size_t num_types)
{
  E3DB_Op *op = E3DB_Op_New(client, E3DB_OP_LIST_RECORDS);
  E3DB_ListRecordsResult *result = xmalloc(sizeof(E3DB_ListRecordsResult));

  result->limit = limit;
  result->offset = offset;

  op->result = result;
  op->free_result = E3DB_ListRecordsResult_Delete;

  // TODO: Also fetch auth token if our access token is expired.
  if (client->access_token == NULL)
  {
    E3DB_InitAuthOp(client, op, E3DB_ListRecords_Request);
  }
  else
  {
    E3DB_ListRecords_InitOp(op);
  }
  printf("AFTR INIT OP");

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

E3DB_GetEAKResultIterator *E3DB_GetEAKResultIterator_GetIterator(E3DB_EncryptedAccessKeyResult *result)
{
  E3DB_GetEAKResultIterator *it = xmalloc(sizeof(*it));
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
  E3DB_GetRecordMetaFromJSON(it->pos, &it->meta);
  return &it->meta;
}

/*
 * {Read Records}
 *
 * We export the most general interface: reading multiple records with an
 * explicit set of fields.
 */

struct _E3DB_ReadRecordsResult
{
  cJSON *json; // entire ciphertext response body
  size_t num_record_ids;
  const char **record_ids; // not owned but maybe should be?
};

struct _E3DB_ReadRecordsResultIterator
{
  cJSON *pos;
  E3DB_RecordMeta meta;
  E3DB_Record record;
};

static void E3DB_ReadRecordsResult_Delete(void *p)
{
  E3DB_ReadRecordsResult *result = p;

  if (result != NULL)
  {
    if (result->json != NULL)
    {
      cJSON_Delete(result->json);
    }
    xfree(result);
  }
}

static int E3DB_ReadRecords_Response(
    E3DB_Op *op, int response_code,
    const char *body, E3DB_HttpHeaderList *headers, size_t num_headers)
{
  if (response_code != 200)
  {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  cJSON *json = cJSON_Parse(body);

  if (json == NULL)
  {
    // TODO: Figure out proper error handling here.
    fprintf(stderr, "Fatal: Parsing ListRecords JSON failed.\n");
    abort();
  }

  /* Wrap the result in an array if it is a single object. */
  if (json->type == cJSON_Object)
  {
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array, json);
    json = array;
  }

  E3DB_ReadRecordsResult *result = op->result;
  result->json = json;

  E3DB_Op_Finish(op);
  return 0;
}

static void E3DB_ReadRecords_InitOp(E3DB_Op *op)
{
  E3DB_ReadRecordsResult *result = op->result;

  // TODO: Make sure at least 1 record ID is specified.

  sds url = sdsnew(op->client->options->api_url);
  url = sdscat(url, "/v1/storage/records/");

  for (size_t i = 0; i < result->num_record_ids; ++i)
  {
    if (i != 0)
      url = sdscat(url, ",");
    url = sdscat(url, result->record_ids[i]);
  }

  // TODO: Add fields to URL

  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = url;
  op->request.http.method = sdsnew("GET");
  op->request.http.body = sdsnew("");
  op->request.http.next_state = E3DB_ReadRecords_Response;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = sdsnew("Bearer ");
  auth_header = sdscat(auth_header, op->client->access_token);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  sdsfree(auth_header);
}

static int E3DB_ReadRecords_Request(E3DB_Op *op, int response_code,
                                    const char *body, E3DB_HttpHeaderList *headers,
                                    size_t num_headers)
{
  E3DB_HandleAuthResponse(op, response_code, body);
  E3DB_ReadRecords_InitOp(op);
  return 0;
}

E3DB_Op *E3DB_ReadRecords_Begin(
    E3DB_Client *client, const char **record_ids, size_t num_record_ids,
    const char *fields[], size_t num_fields)
{
  printf("\nIn E3DB_ReadRecords_Begin\n");

  E3DB_Op *op = E3DB_Op_New(client, E3DB_OP_READ_RECORDS);
  E3DB_ReadRecordsResult *result = xmalloc(sizeof(*result));

  result->record_ids = record_ids;
  result->num_record_ids = num_record_ids;

  op->result = result;
  op->free_result = E3DB_ReadRecordsResult_Delete;

  // TODO: Also fetch auth token if our access token is expired.
  if (client->access_token == NULL)
  {
    printf("\nE3DB_ReadRecords_Begin getting access token\n");
    E3DB_InitAuthOp(client, op, E3DB_ReadRecords_Request);
  }
  else
  {
    printf("\nE3DB_ReadRecords_Begin already have access token\n");

    E3DB_ReadRecords_InitOp(op);
  }
  return op;
}

/* Return the result of a successful "read records" operation. Returns
 * NULL if the operation is not complete. The returned structure has the
 * same lifetime as the containing operation and does not need to be freed. */
E3DB_ReadRecordsResult *E3DB_ReadRecords_GetResult(E3DB_Op *op)
{
  return op->result;
}

/* Return an iterator over the records in a result set. */
E3DB_ReadRecordsResultIterator *E3DB_ReadRecordsResult_GetIterator(E3DB_ReadRecordsResult *r)
{
  E3DB_ReadRecordsResultIterator *it = xmalloc(sizeof(*it));
  it->pos = r->json->child;
  return it;
}

/* Return the result of a successful "get encrypted access key" operation. Returns
 * NULL if the operation is not complete. The returned structure has the
 * same lifetime as the containing operation and does not need to be freed. */
E3DB_EncryptedAccessKeyResult *E3DB_EAK_GetResult(E3DB_Op *op)
{
  return op->result;
}

// /* Return the result of a successful "get encrypted access key" operation. Returns
//  * NULL if the operation is not complete. The returned structure has the
//  * same lifetime as the containing operation and does not need to be freed. */
// cJSON *E3DB_EAK_GetJSON(E3DB_EncryptedAccessKeyResult *op)
// {
//   return op->json;
// }

/* Delete a record result iterator. */
void E3DB_ReadRecordsResultIterator_Delete(E3DB_ReadRecordsResultIterator *it)
{
  assert(it != NULL);
  xfree(it);
}

/* Returns true if a record result iterator is completed. */
int E3DB_ReadRecordsResultIterator_IsDone(E3DB_ReadRecordsResultIterator *it)
{
  assert(it != NULL);
  return (it->pos == NULL);
}

/* Move a record result iterator to the next value. */
void E3DB_ReadRecordsResultIterator_Next(E3DB_ReadRecordsResultIterator *it)
{
  assert(it != NULL);
  assert(it->pos != NULL);
  it->pos = it->pos->next;
}

/* Return the metadata for the current record in the result set. */
E3DB_RecordMeta *E3DB_ReadRecordsResultIterator_GetMeta(E3DB_ReadRecordsResultIterator *it)
{
  printf("it->pos from E3DB_ReadRecordsResultIterator_GetMeta:\n%s\n", it->pos);

  cJSON *meta = cJSON_GetObjectItem(it->pos, "meta");
  printf("cJSON *meta from E3DB_ReadRecordsResultIterator_GetMeta:\n%s\n", *meta);

  if (meta == NULL || meta->type != cJSON_Object)
  {
    fprintf(stderr, "Error: meta field doesn't exist.\n");
    abort();
  }

  E3DB_GetRecordMetaFromJSON(meta, &it->meta);
  return &it->meta;
}

/* Return the record record data for the current record in the result set. */
E3DB_Record *E3DB_ReadRecordsResultIterator_GetData(E3DB_ReadRecordsResultIterator *it)
{
  cJSON *data = cJSON_GetObjectItem(it->pos, "data");

  if (data == NULL || data->type != cJSON_Object)
  {
    fprintf(stderr, "Error: data field doesn't exist.\n");
    abort();
  }

  it->record.json = data;
  return &it->record;
}

/* Return the record record data for the current record in the result set. */
char *E3DB_ReadRecordsResultIterator_GetRecSig(E3DB_ReadRecordsResultIterator *it)
{
  char *rec_sig = cJSON_GetSafeObjectItemString(it->pos, "rec_sig");

  if (rec_sig == NULL)
  {
    fprintf(stderr, "Error: data field doesn't exist.\n");
    abort();
  }
  return rec_sig;
}

E3DB_EAK *E3DB_ResultIterator_GetEAK(E3DB_GetEAKResultIterator *it)
{
  cJSON *EAK = cJSON_GetObjectItem(it->pos, "eak");
  if (EAK == NULL)
  {
    fprintf(stderr, "Error: eak field doesn't exist.\n");
    abort();
  }

  cJSON *signer_id = cJSON_GetObjectItem(it->pos, "signer_id");
  if (signer_id == NULL)
  {
    fprintf(stderr, "Error: signer_id field doesn't exist.\n");
    abort();
  }

  cJSON *authorizer_id = cJSON_GetObjectItem(it->pos, "authorizer_id");
  if (authorizer_id == NULL)
  {
    fprintf(stderr, "Error: authorizer_id field doesn't exist.\n");
    abort();
  }

  cJSON *signer_signing_key = cJSON_GetObjectItem(it->pos, "signer_signing_key");
  if (signer_signing_key == NULL)
  {
    fprintf(stderr, "Error: signer_signing_key field doesn't exist.\n");
    abort();
  }

  cJSON *authorizer_public_key = cJSON_GetObjectItem(it->pos, "authorizer_public_key");
  if (authorizer_public_key == NULL)
  {
    fprintf(stderr, "Error: signer_signing_key field doesn't exist.\n");
    abort();
  }

  it->EAK.eak = cJSON_Print(EAK);
  it->EAK.signer_id = cJSON_Print(signer_id);
  it->EAK.authorizer_id = cJSON_Print(authorizer_id);
  E3DB_GetSignerSigningKeyFromJSON(signer_signing_key, &it->EAK.signer_signing_key);
  E3DB_GetAuthPubKeyFromJSON(authorizer_public_key, &it->EAK.auth_pub_key);

  printf("\nit->EAK.eak: %s\n", it->EAK.eak);
  printf("it->EAK.signer_id: %s\n", it->EAK.signer_id);
  printf("it->EAK.authorizer_id: %s\n", it->EAK.authorizer_id);
  printf("it->EAK.signer_signing_key.ed25519: %s\n", it->EAK.signer_signing_key.ed25519);
  printf("it->EAK.auth_pub_key.curve25519: %s\n", it->EAK.auth_pub_key.curve25519);

  free(EAK);
  free(signer_id);
  free(authorizer_id);
  free(signer_signing_key);
  free(authorizer_public_key);
  return &it->EAK;
}

const char *E3DB_EAK_DecryptEAK(char *eak, char *pubKey, char *privKey)
{
  unsigned char *ak = (unsigned char *)malloc(32);
  size_t eakLength = strlen(eak);
  unsigned char *eak_copy = (char *)malloc(eakLength * sizeof(char) + 1);
  strcpy(eak_copy, eak);
  int i = 0;
  char *p = strtok(eak_copy, ".");
  char *array[2];

  while (p != NULL)
  {
    array[i++] = p;
    p = strtok(NULL, ".");
  }
  unsigned char *decodedKey = base64_decode(array[0]);
  unsigned char *decodedNonce = base64_decode(array[1]);
  unsigned char *decodedPubKey = base64_decode(pubKey);
  unsigned char *decodedPrivKey = base64_decode(privKey);

  unsigned long long clen = strlen((const char *)decodedKey);
  int status = crypto_box_open_easy(ak, decodedKey, clen, decodedNonce, decodedPubKey, decodedPrivKey);
  ak = (char *)realloc(ak, 32 * sizeof(char) + 1);
  ak[32] = '\0';
  printf("\n EAK Decryption Status: %d", status);
  free(eak_copy);
  free(decodedKey);
  free(decodedNonce);
  free(decodedPubKey);
  free(decodedPrivKey);
  return ak;
}

const char *E3DB_RecordFieldIterator_DecryptValue(unsigned char *edata, unsigned char *ak)
{
  size_t edataLength = strlen(edata);
  unsigned char *edata_copy = (char *)malloc(edataLength * sizeof(char) + 1);
  strcpy(edata_copy, edata);
  int i = 0;
  char *p = strtok(edata_copy, ".");
  char *array[4];

  while (p != NULL)
  {
    array[i++] = p;
    p = strtok(NULL, ".");
  }

  unsigned char *decodedDataKey = base64_decode(array[0]);
  unsigned char *decodedDataKeyNonce = base64_decode(array[1]);

  unsigned char *decodedData = base64_decode(array[2]);
  unsigned char *decodedDataNonce = base64_decode(array[3]);

  unsigned long long clen = strlen((const char *)decodedDataKey);
  // Find length of data key cipher:
  int length = 0;
  while (decodedDataKey[length] != '\0' || decodedDataKey[length + 1] != '\0')
  {
    length++;
  }
  // printf("\n Strlen: %d Custom Length: %d ", clen, length);
  unsigned char *dk = (unsigned char *)malloc(32);
  int status = crypto_secretbox_open_easy(dk, decodedDataKey, length, decodedDataKeyNonce, ak);
  printf("\n DK Decryption Status: %d", status);

  unsigned long long dlen = strlen((const char *)decodedData);
  unsigned char *data = (char *)malloc(dlen * sizeof(char));
  // Find length of data cipher:
  length = 0;
  while (decodedData[length] != '\0' || decodedData[length + 1] != '\0')
  {
    length++;
  }
  // printf("\n Strlen: %d Custom Length: %d", dlen, length);
  status = crypto_secretbox_open_easy(data, decodedData, length, decodedDataNonce, dk);
  printf("\n Data Decryption Status: %d", status);
  free(edata_copy);
  free(decodedDataKey);
  free(decodedDataKeyNonce);
  free(decodedData);
  free(decodedDataNonce);
  free(dk);
  return data;
}

static void E3DB_EncryptedAccessKeys_InitOp(E3DB_Op *op)
{
  printf("\nHELLO from E3DB_EncryptedAccessKeys_InitOp\n");
  E3DB_EncryptedAccessKeyResult *result = op->result;

  // TODO: Make sure at least 1 record ID is specified.

  sds url = sdsnew(op->client->options->api_url);
  url = sdscat(url, "/v1/storage/access_keys/");
  url = sdscat(url, result->writer_id);
  url = sdscat(url, "/");
  url = sdscat(url, result->writer_id);
  url = sdscat(url, "/");
  url = sdscat(url, result->writer_id);
  url = sdscat(url, "/");
  url = sdscat(url, result->type);

  printf("\nURL: %s\n", url);

  // TODO: Add fields to URL

  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = url;
  op->request.http.method = sdsnew("GET");
  op->request.http.body = sdsnew("");
  op->request.http.next_state = E3DB_ReadRecords_Response;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = sdsnew("Bearer ");
  auth_header = sdscat(auth_header, op->client->access_token);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  sdsfree(auth_header);
}

static int E3DB_EncryptedAccessKey_Request(E3DB_Op *op, int response_code,
                                           const char *body, E3DB_HttpHeaderList *headers,
                                           size_t num_headers)
{
  // TODO wonder if in the below response i can say "if its 404 or 200" but ill affect the read recorddd
  E3DB_HandleAuthResponse(op, response_code, body);
  E3DB_EncryptedAccessKeys_InitOp(op);
  return 0;
}

E3DB_Op *E3DB_GetEncryptedAccessKeys_Begin(
    E3DB_Client *client, const char **writer_id, const char **user_id, const char **client_id, const char **record_type)
{
  printf("%s", "At the start of E3DB_GetEncryptedAccessKeys_Begin ");

  E3DB_Op *op = E3DB_Op_New(client, E3DB_OP_ENCRYPTED_ACCESS_KEYS);
  E3DB_EncryptedAccessKeyResult *result = xmalloc(sizeof(*result));

  // Set up needed params for call to get encrypted access keys
  result->writer_id = writer_id;
  result->user_id = user_id;
  result->user_id = client_id;
  result->type = record_type;

  op->result = result;
  op->free_result = E3DB_EncryptedAccessKeyResult_Delete;

  // TODO: Also fetch auth token if our access token is expired.
  if (client->access_token == NULL)
  {
    E3DB_InitAuthOp(client, op, E3DB_EncryptedAccessKey_Request);
  }
  else
  {
    E3DB_EncryptedAccessKeys_InitOp(op);
  }
  printf("%s", "At the end of E3DB_GetEncryptedAccessKeys_Begin ");

  return op;
}

// Create Access Key Data
// ---------------------------------------------------------------------------------------------------------------------------------

static int E3DB_CreateAccessKeys_Response(
    E3DB_Op *op, int response_code,
    const char *body, E3DB_HttpHeaderList *headers, size_t num_headers)
{
  printf("%s", "IN DA RESPONSE ");

  if (response_code != 201)
  {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  cJSON *json = cJSON_Parse(body);

  if (json == NULL)
  {
    // TODO: Figure out proper error handling here.
    fprintf(stderr, "Fatal: Parsing ListRecords JSON failed.\n");
    abort();
  }

  /* Wrap the result in an array if it is a single object. */
  if (json->type == cJSON_Object)
  {
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array, json);
    json = array;
  }

  E3DB_ReadRecordsResult *result = op->result;
  result->json = json;

  E3DB_Op_Finish(op);
  return 0;
}
static void E3DB_CreateAccessKeys_InitOp(E3DB_Op *op)
{
  printf("\nHELLO from E3DB_CreateAccessKeys_InitOp\n");
  E3DB_CreateAccessKeyResult *result = op->result;

  // TODO: Make sure at least 1 record ID is specified.

  sds url = sdsnew(op->client->options->api_url);
  url = sdscat(url, "/v1/storage/access_keys/");
  url = sdscat(url, result->writer_id);
  url = sdscat(url, "/");
  url = sdscat(url, result->writer_id);
  url = sdscat(url, "/");
  url = sdscat(url, result->writer_id);
  url = sdscat(url, "/");
  url = sdscat(url, result->type);

  printf("\nURL: %s\n", url);

  cJSON *json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "eak", result->ak);
  char *json_str = cJSON_Print(json);
  // puts(buffer);
  // TODO: Add fields to URL

  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = url;
  op->request.http.method = sdsnew("PUT");
  op->request.http.body = sdsnew(json_str);
  op->request.http.next_state = E3DB_CreateAccessKeys_Response;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = sdsnew("Bearer ");
  auth_header = sdscat(auth_header, op->client->access_token);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  sdsfree(auth_header);
}

static int E3DB_CreateAccessKey_Request(E3DB_Op *op, int response_code,
                                        const char *body, E3DB_HttpHeaderList *headers,
                                        size_t num_headers)
{
  E3DB_HandleAuthResponse(op, response_code, body);
  E3DB_CreateAccessKeys_InitOp(op);
  return 0;
}

static void E3DB_CreateAccessKeyResult_Delete(void *p)
{
  E3DB_CreateAccessKeyResult *result = p;

  if (result != NULL)
  {
    if (result->json != NULL)
    {
      cJSON_Delete(result->json);
    }
    xfree(result);
  }
}

E3DB_Op *E3DB_CreateAccessKeys_Begin(
    E3DB_Client *client, const char **writer_id, const char **user_id, const char **client_id, const char **record_type, const char **reader_public_key)
{

  E3DB_Op *op = E3DB_Op_New(client, E3DB_OP_CREATE_ACCESS_KEYS);
  E3DB_CreateAccessKeyResult *result = xmalloc(sizeof(*result));

  // Generate a Random Secret Key- 32 bytes
  unsigned char *key[SECRET_KEY_SIZE];
  randombytes_buf(key, SECRET_KEY_SIZE);
  // Add Null Terminater
  unsigned char *accessKey = (char *)malloc(SECRET_KEY_SIZE * sizeof(char) + 1);
  strcpy(accessKey, key);
  accessKey[32] = '\0';
  unsigned long long keyLength = strlen((const char *)accessKey);

  // Grab User Private Key
  char *writerKey = client->options->private_key;

  // Grab reader and writer key and decode
  unsigned char *publicKey = base64_decode(reader_public_key);
  unsigned char *privateKey = base64_decode(writerKey);

  // Create Nonce- 24 bytes
  unsigned char *generateNonce[crypto_box_NONCEBYTES];
  randombytes_buf(generateNonce, crypto_box_NONCEBYTES);
  // Add Null Terminater
  unsigned char *nonce = (char *)malloc(crypto_box_NONCEBYTES * sizeof(char) + 1);
  strcpy(nonce, generateNonce);
  nonce[crypto_box_NONCEBYTES] = '\0';

  // Encrypt
  unsigned char *ciphertext[crypto_box_MACBYTES + SECRET_KEY_SIZE];
  // Pass in access key (null terminated) or non null terminated
  int status = crypto_box_easy(ciphertext, accessKey, SECRET_KEY_SIZE, nonce, publicKey, privateKey);

  // Add Null terminator
  unsigned char *newCipher = (char *)malloc((crypto_box_MACBYTES + SECRET_KEY_SIZE) * sizeof(char) + 1);
  strcpy(newCipher, ciphertext);
  newCipher[(crypto_box_MACBYTES + SECRET_KEY_SIZE) * sizeof(char)] = '\0';
  // Encode
  sds ciphertext_base64 = base64_encodeUrl(newCipher);
  sds nonce_base64 = base64_encodeUrl(nonce);

  // Set up EAK
  // Join the EAK.Nonce
  unsigned char *encryptedAccessKey = (char *)malloc(strlen(ciphertext_base64) + strlen(nonce_base64) + 1);
  strcpy(encryptedAccessKey, ciphertext_base64);
  strncat(encryptedAccessKey, ".", 1);
  strncat(encryptedAccessKey, nonce_base64, strlen(nonce_base64) + 1);

  result->writer_id = writer_id;
  result->user_id = user_id;
  result->type = record_type;
  result->ak = encryptedAccessKey;

  op->result = result;
  op->free_result = E3DB_CreateAccessKeyResult_Delete;

  // TODO: Also fetch auth token if our access token is expired.
  if (client->access_token == NULL)
  {
    printf("%s", "Access key is null");
    E3DB_InitAuthOp(client, op, E3DB_CreateAccessKey_Request);
  }
  else
  {
    printf("%s", "Access key is NOT null");
    E3DB_CreateAccessKeys_InitOp(op);
  }

  return op;
}

// Write Data
// ---------------------------------------------------------------------------------------------------------------------------------

struct _E3DB_WriteRecordsResult
{
  cJSON *json; // entire ciphertext response body
  const char **record_type;
  cJSON *data;
  cJSON *meta;
};

struct RecordMetaData
{
  cJSON *json; // entire ciphertext response body
  const char **record_id;
  const char **writer_id;
  const char **user_id;
  const char **type;
  const char **version;
  const char **plain;
  const time_t **created;
  const time_t *last_modified;
};

struct Record
{
  const char **data;
  const struct RecordMetaData *meta;
};

/* Return the result of a successful "read records" operation. Returns
 * NULL if the operation is not complete. The returned structure has the
 * same lifetime as the containing operation and does not need to be freed. */
E3DB_WriteRecordsResult *E3DB_WriteRecords_GetResult(E3DB_Op *op)
{
  return op->result;
}

static void E3DB_WriteRecordsResult_Delete(void *p)
{
  E3DB_WriteRecordsResult *result = p;

  if (result != NULL)
  {
    if (result->json != NULL)
    {
      cJSON_Delete(result->json);
    }
    xfree(result);
  }
}

static int E3DB_WriteRecords_Response(
    E3DB_Op *op, int response_code,
    const char *body, E3DB_HttpHeaderList *headers, size_t num_headers)
{
  if (response_code != 201)
  {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  cJSON *json = cJSON_Parse(body);

  if (json == NULL)
  {
    // TODO: Figure out proper error handling here.
    fprintf(stderr, "Fatal: Parsing ListRecords JSON failed.\n");
    abort();
  }

  /* Wrap the result in an array if it is a single object. */
  if (json->type == cJSON_Object)
  {
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array, json);
    json = array;
  }

  E3DB_WriteRecordsResult *result = op->result;
  result->json = json;

  E3DB_Op_Finish(op);
  return 0;
}
const char *SignDocumentWithPrivateKey(char *document, char *privateSigningKey)
{
  // Raw Signing key
  unsigned char *decodedPrivateSigningKey = base64_decode(privateSigningKey);
  unsigned char sig[crypto_sign_BYTES];

  int status = crypto_sign_detached(sig, NULL, document, strlen(document), decodedPrivateSigningKey);
  printf("Status of Signature %d", status);

  // Add Null terminator
  unsigned char *signedDocument = (char *)malloc(crypto_sign_BYTES * sizeof(char) + 1);
  strcpy(signedDocument, sig);
  signedDocument[crypto_sign_BYTES * sizeof(char)] = '\0';

  return base64_encode(signedDocument);
}

static void E3DB_WriteRecords_InitOp(E3DB_Op *op)
{
  E3DB_WriteRecordsResult *result = op->result;

  sds url = sdsnew(op->client->options->api_url);
  url = sdscat(url, "/v1/storage/records/");

  // Meta JSON Object
  cJSON *metaJSONObject = cJSON_CreateObject();
  cJSON_AddStringToObject(metaJSONObject, "writer_id", op->client->options->client_id);
  cJSON_AddStringToObject(metaJSONObject, "user_id", op->client->options->client_id);
  cJSON_AddStringToObject(metaJSONObject, "type", result->record_type);
  // this is wrong, this needs to be a map[string]string
  cJSON_AddItemToObject(metaJSONObject, "plain", result->meta);
  char *metaJSON = cJSON_Print(metaJSONObject);
  printf("META JSON %s \n\n\n", metaJSON);

  // Record JSON Object
  cJSON *recordWriteRequestJSON = cJSON_CreateObject();
  // this is wrong, this needs to be a map[string]string
  cJSON_AddItemToObject(recordWriteRequestJSON, "data", result->data);
  cJSON_AddItemToObject(recordWriteRequestJSON, "meta", metaJSONObject);
  char *request = cJSON_Print(recordWriteRequestJSON);
  printf("request JSON %s", request);

  char *signature = SignDocumentWithPrivateKey(request, op->client->options->private_signing_key);
  cJSON_AddStringToObject(recordWriteRequestJSON, "rec_sig", signature);
  char *signedRequest = cJSON_Print(recordWriteRequestJSON);

  printf("signed request JSON %s", signedRequest);

  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = url;
  op->request.http.method = sdsnew("POST");
  op->request.http.body = sdsnew(signedRequest);
  op->request.http.next_state = E3DB_WriteRecords_Response;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = sdsnew("Bearer ");
  auth_header = sdscat(auth_header, op->client->access_token);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  sdsfree(auth_header);
}

static int E3DB_WriteRecords_Request(E3DB_Op *op, int response_code,
                                     const char *body, E3DB_HttpHeaderList *headers,
                                     size_t num_headers)
{
  E3DB_HandleAuthResponse(op, response_code, body);
  E3DB_WriteRecords_InitOp(op);
  return 0;
}

const char *EncryptRecordField(char *ak, char *field)
{

  // TODO TEST THIS BECAUSE I THINK THE PROBLEM IS HERE OR WITH THE DATA ARRAY FORMAT
  // Create dk
  unsigned char *key[SECRET_KEY_SIZE];
  randombytes_buf(key, SECRET_KEY_SIZE);
  // Add Null Terminater
  unsigned char *dk = (char *)malloc(SECRET_KEY_SIZE * sizeof(char) + 1);
  strcpy(dk, key);
  dk[32] = '\0';

  // Create efN
  unsigned char *generateNonce[crypto_box_NONCEBYTES];
  randombytes_buf(generateNonce, crypto_box_NONCEBYTES);
  // Add Null Terminater
  unsigned char *efN = (char *)malloc(crypto_box_NONCEBYTES * sizeof(char) + 1);
  strcpy(efN, generateNonce);
  efN[crypto_box_NONCEBYTES] = '\0';

  // Encrypt Symmetric
  unsigned char *ciphertext[crypto_box_MACBYTES + strlen(field)];
  crypto_secretbox_easy(ciphertext, field, strlen(field), efN, dk);
  // Add Null terminator
  unsigned char *ef = (char *)malloc((crypto_box_MACBYTES + strlen(field)) * sizeof(char) + 1);
  strcpy(ef, ciphertext);
  ef[(crypto_box_MACBYTES + strlen(field)) * sizeof(char)] = '\0';

  // Create edkN
  unsigned char *generateedkNNonce[crypto_box_NONCEBYTES];
  randombytes_buf(generateedkNNonce, crypto_box_NONCEBYTES);
  // Add Null Terminater
  unsigned char *edkN = (char *)malloc(crypto_box_NONCEBYTES * sizeof(char) + 1);
  strcpy(edkN, generateedkNNonce);
  edkN[crypto_box_NONCEBYTES] = '\0';

  // Encrypt Symmetric
  unsigned char *ciphertextedk[crypto_box_MACBYTES + strlen(dk)];
  crypto_secretbox_easy(ciphertextedk, dk, strlen(dk), edkN, ak);
  // Add Null terminator
  unsigned char *edk = (char *)malloc((crypto_box_MACBYTES + strlen(dk)) * sizeof(char) + 1);
  strcpy(edk, ciphertext);
  edk[(crypto_box_MACBYTES + strlen(dk)) * sizeof(char)] = '\0';

  // Create dotted quad
  sds edk_base64 = base64_encodeUrl(edk);
  sds edkN_base64 = base64_encodeUrl(edkN);
  sds ef_base64 = base64_encodeUrl(ef);
  sds efN_base64 = base64_encodeUrl(efN);

  // edk.edkN.ef.efN
  unsigned char *encryptedField = (char *)malloc(strlen(edk_base64) + strlen(edkN_base64) + strlen(ef_base64) + strlen(efN_base64) + 3);
  strcpy(encryptedField, edk_base64);
  strncat(encryptedField, ".", 1);
  strncat(encryptedField, edkN_base64, strlen(edkN_base64));
  strncat(encryptedField, ".", 1);
  strncat(encryptedField, ef_base64, strlen(ef_base64));
  strncat(encryptedField, ".", 1);
  strncat(encryptedField, efN_base64, strlen(efN_base64));

  return encryptedField;
}

E3DB_Op *E3DB_WriteRecord_Begin(
    E3DB_Client *client, const char **record_type, const char **data, const char **meta, const char **accessKey)
{
  E3DB_Op *op = E3DB_Op_New(client, E3DB_OP_WRITE_RECORD);
  E3DB_WriteRecordsResult *result = xmalloc(sizeof(*result));

  // Encrypt Record Begins ------------------------------------------------------
  // right now we are not passing in json objects or tags...... we need to do both

  char *encryptedField = EncryptRecordField(accessKey, data);

  cJSON *dataJSON = cJSON_CreateObject();
  cJSON_AddStringToObject(dataJSON, "dataKey", encryptedField);

  cJSON *metaJson = cJSON_CreateObject();
  cJSON_AddStringToObject(metaJson, "metaKey", meta);

  result->record_type = record_type;
  result->data = dataJSON;
  result->meta = metaJson;

  op->result = result;
  op->free_result = E3DB_WriteRecordsResult_Delete;

  // TODO: Also fetch auth token if our access token is expired.
  if (client->access_token == NULL)
  {
    E3DB_InitAuthOp(client, op, E3DB_WriteRecords_Request);
  }
  else
  {
    E3DB_WriteRecords_InitOp(op);
  }
  return op;
}
