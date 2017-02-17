/*
 * list-records.c
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "e3db_core.h"
#include "e3db_mem.h"
#include "e3db_base64.h"

// TODO: It might make more sense to use an OpenSSL BIO for this?
typedef struct {
  char *buf;
  size_t len;
} MemBuffer;

static void InitMemBuffer(MemBuffer *buf)
{
  buf->len = 0;
  buf->buf = malloc(buf->len + 1);
  if (buf->buf == NULL) {
    fprintf(stderr, "Fatal: Out of memory.\n");
    exit(1);
  }

  buf->buf[0] = '\0';
}

static void FreeMemBuffer(MemBuffer *buf)
{
  free(buf->buf);
}

static size_t WriteMemBuffer(void *ptr, size_t size, size_t nmemb, MemBuffer *buf)
{
  size_t new_len = buf->len + size * nmemb;
  buf->buf = realloc(buf->buf, new_len + 1);
  if (buf->buf == NULL) {
    fprintf(stderr, "Fatal: Out of memory.\n");
    exit(1);
  }

  memcpy(buf->buf + buf->len, ptr, size * nmemb);
  buf->buf[new_len] = '\0';
  buf->len = new_len;

  return size * nmemb;
}

/* Complete an E3DB operation using Curl for HTTP requests. */
int CurlRunOp(E3DB_Op *op)
{
  CURL *curl;

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "Fatal: Curl initialization failed.\n");
    exit(1);
  }

  while (!E3DB_Op_IsDone(op)) {
    if (E3DB_Op_IsHttpState(op)) {
      E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
      MemBuffer buf;
      InitMemBuffer(&buf);

      struct curl_slist *chunk = NULL;
      E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

      while (header != NULL) {
        chunk = curl_slist_append(chunk, E3DB_HttpHeader_GetValue(header));
        header = E3DB_HttpHeader_GetNext(header);
      }

      curl_easy_setopt(curl, CURLOPT_URL, E3DB_Op_GetHttpUrl(op));
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemBuffer);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

      CURLcode res = curl_easy_perform(curl);
      if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
      }

      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      E3DB_Op_FinishHttpState(op, response_code, buf.buf, NULL, 0);

      curl_slist_free_all(chunk);
      FreeMemBuffer(&buf);
    }
  }

  curl_easy_cleanup(curl);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 3) {
    fprintf(stderr, "Usage: %s API_KEY_ID API_SECRET\n", argv[0]);
    return 1;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);

  E3DB_ClientOptions *opts = E3DB_ClientOptions_New();
  E3DB_ClientOptions_SetApiKey(opts, argv[1]);
  E3DB_ClientOptions_SetApiSecret(opts, argv[2]);

  /* Ownership of `opts' passes to `client', no need to delete. */
  E3DB_Client *client = E3DB_Client_New(opts);

  E3DB_Op *op = E3DB_ListRecords_Begin(client, 100, 0, NULL, NULL, 0);
  CurlRunOp(op);

  E3DB_ListRecordsResult *result = E3DB_ListRecords_GetResult(op);
  E3DB_ListRecordsResultIterator *it = E3DB_ListRecordsResult_GetIterator(result);

  printf("%-40s %-40s %s\n", "Record ID", "Writer ID", "Type");
  printf("--------------------------------------------------------------------------------------------------------\n");

  while (!E3DB_ListRecordsResultIterator_IsDone(it)) {
    E3DB_ListRecordsResultIterator_Get(it);
    E3DB_RecordMeta *meta = E3DB_ListRecordsResultIterator_Get(it);

    printf("%-40s %-40s %s\n",
      E3DB_RecordMeta_GetRecordId(meta),
      E3DB_RecordMeta_GetWriterId(meta),
      E3DB_RecordMeta_GetType(meta));

    E3DB_ListRecordsResultIterator_Next(it);
  }

  E3DB_ListRecordsResultIterator_Delete(it);
  E3DB_Op_Delete(op);

  E3DB_Client_Delete(client);
  curl_global_cleanup();

  return 0;
}
