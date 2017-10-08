/*
 * e3db_core.c
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cJSON.h"
#include "utlist.h"
#include "sds.h"

#include "e3db_core.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

/*
 * {JSON Utilities}
 */

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

/* Utility function to get a required JSON object field. */
static cJSON *cJSON_GetRequiredObjectItem(cJSON *json, const char *name, int type)
{
  cJSON *obj = cJSON_GetObjectItem(json, name);

  if (obj == NULL || obj->type != type) {
    fprintf(stderr, "Missing required JSON field '%s'\n", name);
    abort();
  }

  return obj;
}

/*
 * {Client Options}
 */

#define DEFAULT_API_URL    "https://api.e3db.com/v1/storage"
#define DEFAULT_AUTH_URL   "https://api.e3db.com/v1/auth"
#define DEFAULT_API_KEY    ""
#define DEFAULT_API_SECRET ""

struct _E3DB_ClientOptions {
  sds api_url;
  sds api_key;
  sds api_secret;
  sds client_id;
  uint8_t public_key[crypto_box_PUBLICKEYBYTES];
  uint8_t private_key[crypto_box_SECRETKEYBYTES];
};

E3DB_ClientOptions *E3DB_ClientOptions_New(void)
{
  E3DB_ClientOptions *opts = xmalloc(sizeof(E3DB_ClientOptions));

  opts->api_url    = sdsnew(DEFAULT_API_URL);
  opts->api_key    = sdsnew(DEFAULT_API_KEY);
  opts->api_secret = sdsnew(DEFAULT_API_SECRET);
  opts->client_id  = sdsnew("");

  return opts;
}

void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts)
{
  sdsfree(opts->api_url);
  sdsfree(opts->api_key);
  sdsfree(opts->api_secret);
  sdsfree(opts->client_id);
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

void E3DB_ClientOptions_SetClientId(E3DB_ClientOptions *opts, const char *client_id)
{
  sdsfree(opts->client_id);
  opts->client_id = sdsnew(client_id);
}

void E3DB_ClientOptions_SetPublicKey(E3DB_ClientOptions *opts, const char *public_key)
{
	sodium_base642bin(opts->public_key, crypto_box_PUBLICKEYBYTES, public_key, strlen(public_key),
                    "", NULL, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

void E3DB_ClientOptions_SetPrivateKey(E3DB_ClientOptions *opts, const char *private_key)
{
  sodium_base642bin(opts->private_key, crypto_box_SECRETKEYBYTES, private_key, strlen(private_key),
                    "", NULL, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

/*
 * {Clients}
 */

struct _E3DB_Client {
  E3DB_ClientOptions *options;
  sds access_token;
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
  if (client->access_token) {
    sdsfree(client->access_token);
  }
  xfree(client);
}

/*
 * {Operations and Events}
 */

typedef enum {
  E3DB_OP_QUERY,
} E3DB_OpType;

typedef enum {
  E3DB_OP_STATE_DONE,
  E3DB_OP_STATE_HTTP,
  E3DB_OP_STATE_CONFIG,
  E3DB_OP_STATE_KEY,
} E3DB_OpState;

typedef int (*E3DB_Op_HttpNextStateFn)(E3DB_Op *op, int response_code,
  const char *body, E3DB_HttpHeaderList *headers, size_t num_headers);

struct _E3DB_Op {
  E3DB_Client *client;
  E3DB_OpType type;
  E3DB_OpState state;

  /* Information for the caller about the current state. */
  union {
    struct {
      sds method;
      sds url;
      sds body;
      E3DB_HttpHeaderList *headers;
      E3DB_Op_HttpNextStateFn next_state;
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
  switch (op->state) {
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
  char *name;
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
  hdr->name  = sdsnew(name);
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
 * {Crypto Operations}
 */

#if 0
static void print_hex(const uint8_t *bytes, size_t len)
{
  for (size_t i = 0; i < len; ++i) {
    printf("%02x", bytes[i]);
  }

  printf("\n");
}
#endif

static void base64url_decode_with_len(uint8_t *dest, size_t dest_len, const char *src, size_t *len_out)
{
  sodium_base642bin(dest, dest_len, src, strlen(src), "", len_out, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

static void base64url_decode(uint8_t *dest, size_t dest_len, const char *src)
{
  sodium_base642bin(dest, dest_len, src, strlen(src), "", NULL, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

static int E3DB_DecryptEAK(E3DB_Client *client, uint8_t *ak_out, const char *eak,
                           const char *authorizer_pubK)
{
  uint8_t pubK_bytes[crypto_box_PUBLICKEYBYTES];
  uint8_t eak_bytes[crypto_secretbox_KEYBYTES + crypto_box_MACBYTES];
  uint8_t eakN_bytes[crypto_box_NONCEBYTES];

  int count;
  sds *tokens = sdssplitlen(eak, strlen(eak), ".", 1, &count);
  if (count != 2) {
    fprintf(stderr, "Fatal: Malformed EAK in encrypted record.\n");
    abort();
  }

  base64url_decode(pubK_bytes, sizeof(pubK_bytes), authorizer_pubK);
  base64url_decode(eak_bytes,  sizeof(eak_bytes),  tokens[0]);
  base64url_decode(eakN_bytes, sizeof(eakN_bytes), tokens[1]);

  sdsfreesplitres(tokens, count);

  return crypto_box_open_easy(ak_out, eak_bytes, sizeof(eak_bytes),
                              eakN_bytes, pubK_bytes,
                              client->options->private_key);
}

static int E3DB_DecryptField(E3DB_Client *client, uint8_t *field_out,
                             const char *c, size_t c_len, const uint8_t *ak)
{
  uint8_t edk[crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES];
  uint8_t edkN[crypto_secretbox_NONCEBYTES];
  uint8_t ef[c_len];    // larger than needed but reasonable upper bound
  uint8_t efN[crypto_secretbox_NONCEBYTES];
  uint8_t dk[crypto_secretbox_KEYBYTES];

  size_t ef_len;
  int count;
  sds *tokens;

  tokens = sdssplitlen(c, strlen(c), ".", 1, &count);
  if (count != 4) {
    fprintf(stderr, "Fatal: Malformed encrypted field in record.\n");
    abort();
  }

  base64url_decode         (edk,  sizeof(edk),  tokens[0]);
  base64url_decode         (edkN, sizeof(edkN), tokens[1]);
  base64url_decode_with_len(ef,   sizeof(ef),   tokens[2], &ef_len);
  base64url_decode         (efN,  sizeof(efN),  tokens[3]);

  sdsfreesplitres(tokens, count);

  if (crypto_secretbox_open_easy(dk, edk, sizeof(edk), edkN, ak) < 0) {
    fprintf(stderr, "Error: Decryption of EDK failed.\n");
    return -1;
  }

  if (crypto_secretbox_open_easy(field_out, ef, ef_len, efN, dk) < 0) {
    fprintf(stderr, "Error: Decryption of field failed.\n");
    return -1;
  }

  field_out[ef_len - crypto_secretbox_MACBYTES] = '\0';
  return 0;
}

static int E3DB_DecryptRecord(E3DB_Client *client, cJSON *record)
{
  cJSON *access_key = cJSON_GetRequiredObjectItem(record, "access_key", cJSON_Object);
  cJSON *data = cJSON_GetRequiredObjectItem(record, "record_data", cJSON_Object);
  cJSON *eak = cJSON_GetRequiredObjectItem(access_key, "eak", cJSON_String);
  cJSON *apk = cJSON_GetRequiredObjectItem(access_key, "authorizer_public_key", cJSON_Object);
  cJSON *pubK = cJSON_GetRequiredObjectItem(apk, "curve25519", cJSON_String);

  uint8_t ak[crypto_secretbox_KEYBYTES];

  if (E3DB_DecryptEAK(client, ak, eak->valuestring, pubK->valuestring) < 0) {
    fprintf(stderr, "Fatal: Decryption of record EAK failed authentication.\n");
    abort();
  }

  cJSON *f;
  cJSON_ArrayForEach(f, data) {
    char *field = xmalloc(strlen(f->valuestring));
    if (E3DB_DecryptField(client, (void *)field, f->valuestring, strlen(f->valuestring), ak) < 0) {
      fprintf(stderr, "Fatal: Decryption of record field '%s' failed.\n", f->string);
      abort();
    }

    // Poke the new value directly into the JSON. This relies a little bit
    // on knowing how cJSON implements string values, but should be safe.
    xfree(f->valuestring);
    f->valuestring = field;
  }

  return 0;
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

static void E3DB_GetRecordMetaFromJSON(cJSON *json, E3DB_RecordMeta *meta)
{
  meta->record_id = cJSON_GetSafeObjectItemString(json, "record_id");
  meta->writer_id = cJSON_GetSafeObjectItemString(json, "writer_id");
  meta->user_id   = cJSON_GetSafeObjectItemString(json, "user_id");
  meta->type      = cJSON_GetSafeObjectItemString(json, "type");
}

struct _E3DB_Record {
  cJSON *json;        // "data" field within record
};

struct _E3DB_RecordFieldIterator {
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
  if (j == NULL) {
    fprintf(stderr, "Error: Field '%s' doesn't exist.\n", field);
    return NULL;
  }

  if (j->type != cJSON_String) {
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
  if (response_code != 200) {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  // TODO: Factor this all out into a helper function.
  // Parse the response body then extract and store the access token.
  cJSON *json = cJSON_Parse(body);

  if (json == NULL) {
    // TODO: Error handling.
    fprintf(stderr, "Fatal: Unable to parse JSON response.\n");
    abort();
  }

  sdsfree(op->client->access_token);
  op->client->access_token = sdsnew(cJSON_GetSafeObjectItemString(json, "access_token"));

  E3DB_Op_Finish(op);
}

/**
 * Initialize an E3DB operation to make a request to the authentication
 * service to obtain an access token.
 */
static void E3DB_InitAuthOp(E3DB_Client *client, E3DB_Op *op, E3DB_Op_HttpNextStateFn next_state)
{
  op->state = E3DB_OP_STATE_HTTP;
  // TODO: Allow overriding the auth URL.
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

/*
 * {Query}
 */

typedef struct _E3DB_QueryResult {
  cJSON *json;
  E3DB_QueryOptions *options;
} E3DB_QueryResult;

typedef struct _E3DB_QueryResultIterator {
  cJSON *pos;               // never needs freeing
  E3DB_RecordMeta meta;     // reused to avoid allocations on iteration
  E3DB_Record record;
} E3DB_QueryResultIterator;

void E3DB_QueryOptions_SetDefault(E3DB_QueryOptions *options)
{
  options->writer_ids     = NULL;
  options->num_writer_ids = 0;
  options->record_ids     = NULL;
  options->num_record_ids = 0;
  options->types          = NULL;
  options->num_types      = 0;
  options->include_data   = 1;
  options->page_size      = 50;
  options->after_index    = 0;
  options->raw            = 0;
}

static void E3DB_QueryResult_Delete(void *p)
{
  E3DB_QueryResult *result = p;

  if (result->json != NULL) {
    cJSON_Delete(result->json);
  }

  xfree(result);
}

/* State function called to handle a page's worth of search results. */
static int E3DB_Query_Response(E3DB_Op *op, int response_code, const char *body,
                               E3DB_HttpHeaderList *headers, size_t num_headers)
{
  if (response_code != 200) {
    // TODO: Handle non-successful responses.
    fprintf(stderr, "Fatal: Error response from E3DB API: %d\n", response_code);
    abort();
  }

  cJSON *json = cJSON_Parse(body);

  if (json == NULL) {
    fprintf(stderr, "Fatal: Parsing Query JSON response failed.\n");
    abort();
  }

  //puts(cJSON_Print(json));

  E3DB_QueryResult *result = op->result;
  result->json = json;

  // If data is present and the raw option isn't set, decrypt
  // the results in-place.
  if (result->options->include_data && !result->options->raw) {
    cJSON *results = cJSON_GetObjectItem(result->json, "results");
    cJSON *record;

    if (results == NULL || results->type != cJSON_Array) {
      fprintf(stderr, "Fatal: Missing results in query response.\n");
      abort();
    }

    cJSON_ArrayForEach(record, results) {
      E3DB_DecryptRecord(op->client, record);
    }
  }

  E3DB_Op_Finish(op);
  return 0;
}

/* Convert query options to a JSON structure for POSTing to the query
 * endpoint. */
static cJSON *E3DB_Query_OptionsJSON(E3DB_QueryOptions *options)
{
  cJSON *json = cJSON_CreateObject();

  cJSON_AddItemToObjectCS(json, "count", cJSON_CreateNumber(options->page_size));
  cJSON_AddItemToObjectCS(json, "include_data", cJSON_CreateBool(options->include_data));
  cJSON_AddItemToObjectCS(json, "include_all_writers", cJSON_CreateBool(options->include_all_writers));
  cJSON_AddItemToObjectCS(json, "after_index", cJSON_CreateNumber(options->after_index));

  if (options->num_record_ids != 0) {
    cJSON_AddItemToObjectCS(json, "record_ids",
      cJSON_CreateStringArray(options->record_ids, options->num_record_ids));
  }

  if (options->num_writer_ids != 0) {
    cJSON_AddItemToObjectCS(json, "writer_ids",
      cJSON_CreateStringArray(options->writer_ids, options->num_writer_ids));
  }

  if (options->num_types != 0) {
    cJSON_AddItemToObjectCS(json, "content_types",
      cJSON_CreateStringArray(options->types, options->num_types));
  }

  return json;
}

/* Convert query options to JSON text for the query endpoint. */
static sds E3DB_Query_OptionsBody(E3DB_QueryOptions *options)
{
  cJSON *options_json = E3DB_Query_OptionsJSON(options);
  char *options_text = cJSON_PrintUnformatted(options_json);
  sds options_sds = sdsnew(options_text);
  free(options_text);
  cJSON_Delete(options_json);

  return options_sds;
}

/* Initialize an operation to perform an HTTP POST of search options. */
static int E3DB_Query_InitOp(E3DB_Op *op)
{
  E3DB_QueryResult *result = op->result;

  op->state = E3DB_OP_STATE_HTTP;
  op->request.http.url = sdscatprintf(sdsempty(), "%s/search", op->client->options->api_url);
  op->request.http.method = sdsnew("POST");
  op->request.http.body = E3DB_Query_OptionsBody(result->options);
  op->request.http.next_state = E3DB_Query_Response;
  op->request.http.headers = E3DB_HttpHeaderList_New();

  sds auth_header = sdsnew("Bearer ");
  auth_header = sdscat(auth_header, op->client->access_token);
  E3DB_HttpHeaderList_Add(op->request.http.headers, "Authorization", auth_header);
  sdsfree(auth_header);
  return 0;
}

/* State function called to build a search request after an authentication
 * response has completed. */
static int E3DB_Query_Request(E3DB_Op *op, int response_code, const char *body,
                              E3DB_HttpHeaderList *headers, size_t num_headers)
{
  E3DB_HandleAuthResponse(op, response_code, body);
  E3DB_Query_InitOp(op);
  return 0;
}

E3DB_Op *E3DB_Query_Begin(E3DB_Client *client, E3DB_QueryOptions *options)
{
  E3DB_Op *op = E3DB_Op_New(client, E3DB_OP_QUERY);
  E3DB_QueryResult *result = xmalloc(sizeof(E3DB_QueryResult));

  result->options = options;

  op->result = result;
  op->free_result = E3DB_QueryResult_Delete;

  if (client->access_token == NULL)
    E3DB_InitAuthOp(client, op, E3DB_Query_Request);
  else
    E3DB_Query_InitOp(op);

  return op;
}

int E3DB_QueryResult_GetCount(E3DB_QueryResult *result)
{
  cJSON *j = cJSON_GetObjectItem(result->json, "results");

  if (j == NULL || j->type != cJSON_Array)
    return 0;

  return cJSON_GetArraySize(j);
}

E3DB_QueryResult *E3DB_Query_GetResult(E3DB_Op *op)
{
  return op->result;
}

int E3DB_QueryResult_GetLastIndex(E3DB_QueryResult *result)
{
  cJSON *j = cJSON_GetObjectItem(result->json, "last_index");

  if (j != NULL && j->type == cJSON_Number) {
    return j->valueint;
  } else {
    fprintf(stderr, "Warning: last_index field missing in query result\n");
    return 0;
  }
}

E3DB_QueryResultIterator *E3DB_QueryResult_GetIterator(E3DB_QueryResult *result)
{
  E3DB_QueryResultIterator *it = xmalloc(sizeof(*it));
  cJSON *results = cJSON_GetObjectItem(result->json, "results");

  if (results == NULL || results->type != cJSON_Array) {
    fprintf(stderr, "Error: Query results not present or not array\n");
    abort();
  }

  it->pos = results->child;
  return it;
}

void E3DB_QueryResultIterator_Delete(E3DB_QueryResultIterator *it)
{
  assert(it != NULL);
  xfree(it);
}

int E3DB_QueryResultIterator_IsDone(E3DB_QueryResultIterator *it)
{
  assert(it != NULL);
  return (it->pos == NULL);
}

void E3DB_QueryResultIterator_Next(E3DB_QueryResultIterator *it)
{
  assert(it != NULL);
  assert(it->pos != NULL);
  it->pos = it->pos->next;
}

E3DB_RecordMeta *E3DB_QueryResultIterator_GetMeta(E3DB_QueryResultIterator *it)
{
  cJSON *meta = cJSON_GetObjectItem(it->pos, "meta");

  if (meta == NULL || meta->type != cJSON_Object) {
    fprintf(stderr, "Error: meta field doesn't exist.\n");
    abort();
  }

  E3DB_GetRecordMetaFromJSON(meta, &it->meta);
  return &it->meta;
}

E3DB_Record *E3DB_QueryResultIterator_GetData(E3DB_QueryResultIterator *it)
{
  cJSON *data = cJSON_GetObjectItem(it->pos, "record_data");

  if (data == NULL || data->type != cJSON_Object) {
    fprintf(stderr, "Error: record_data field doesn't exist.\n");
    abort();
  }

  it->record.json = data;
  return &it->record;
}

