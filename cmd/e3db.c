/*
 * e3db.c
 *
 * Copyright (C) 2017, Tozny, LLC.
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

#include "e3db_core.h"
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
  "  ls                   list my records\n"
  "  read                 read records\n";

/* Callback function for libcurl to write data received from an HTTP
 * request to an OpenSSL BIO. Returns the number of bytes written. */
size_t write_body(void *ptr, size_t size, size_t nmemb, BIO *bio)
{
  size_t len = size * nmemb;
  int result;

  if ((result = BIO_write(bio, ptr, len)) < 0) {
    fprintf(stderr, "write_body: BIO_write failed\n");
    abort();
  }

  return (size_t)result;
}

/* Callback function for libcurl to read data that should be supplied
 * as the body in an HTTP POST/PUT/etc request, from an OpenSSL BIO.
 * Returns the number of bytes read. */
size_t read_body(void *ptr, size_t size, size_t nmemb, BIO *bio)
{
  size_t len = size * nmemb;
  int result;

  if ((result = BIO_read(bio, ptr, len)) < 0) {
    fprintf(stderr, "read_body: BIO_read failed\n");
    abort();
  }

  return (size_t)result;
}

/* Complete an E3DB operation using libcurl for HTTP requests. */
int curl_run_op(E3DB_Op *op)
{
  CURL *curl;

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "Fatal: Curl initialization failed.\n");
    exit(1);
  }

  while (!E3DB_Op_IsDone(op)) {
    if (E3DB_Op_IsHttpState(op)) {
      curl_easy_reset(curl);

      const char *method = E3DB_Op_GetHttpMethod(op);
      E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
      BIO *write_bio = BIO_new(BIO_s_mem());

      struct curl_slist *chunk = NULL;
      E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

      while (header != NULL) {
        sds header_text = sdscatprintf(sdsempty(), "%s: %s",
          E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
        chunk = curl_slist_append(chunk, header_text);
        sdsfree(header_text);

        header = E3DB_HttpHeader_GetNext(header);
      }

      if (!strcmp(method, "POST")) {
        const char *post_body = E3DB_Op_GetHttpBody(op);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
      } else if (!strcmp(method, "GET")) {
        // nothing special for GET
      } else {
        fprintf(stderr, "Unsupported method: %s\n", method);
        abort();
      }

      curl_easy_setopt(curl, CURLOPT_URL, E3DB_Op_GetHttpUrl(op));
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);      // change to '1L' for debug logging
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_bio);

      CURLcode res = curl_easy_perform(curl);
      if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
      }

      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

      char *body;
      BIO_write(write_bio, "\0", 1);
      BIO_get_mem_data(write_bio, &body);
      E3DB_Op_FinishHttpState(op, response_code, body, NULL, 0);

      BIO_free_all(write_bio);
      curl_slist_free_all(chunk);
    } else {
      fprintf(stderr, "Error: Unexpected op state\n");
      abort();
    }
  }

  curl_easy_cleanup(curl);
  return 0;
}

/* Get the user's home directory.
 *
 * TODO: Support Windows. */
sds get_home_dir(void)
{
  char *home;

  if ((home = getenv("HOME")) != NULL) {
    return sdsnew(home);
  }

  uid_t uid = getuid();
  struct passwd *pw = getpwuid(uid);

  if (pw == NULL) {
    fprintf(stderr, "Error: Unable to get user home directory.\n");
    exit(1);
  }

  return sdsnew(pw->pw_dir);
}

/* Read a required string value from a JSON object. */
cJSON *get_config_value(cJSON *json, const char *name)
{
  cJSON *val = cJSON_GetObjectItem(json, name);
  if (val == NULL || val->type != cJSON_String) {
    fprintf(stderr, "Error: Missing field '%s' in configuration file.\n", name);
    exit(1);
  }

  return val;
}

/* Load the user's e3db configuration into an E3DB_ClientOptions. */
E3DB_ClientOptions *load_config(void)
{
  sds config_file = sdscat(get_home_dir(), "/.tozny/e3db.json");
  FILE *in;

  if ((in = fopen(config_file, "r")) == NULL) {
    fprintf(stderr, "Error: Unable to open E3DB configuration file.\n");
    // TODO: Point the user to a registration flow.
    exit(1);
  }

  sds config = sdsempty();

  while (!feof(in)) {
    char buf[4096];
    size_t len;

    len = fread(buf, 1, sizeof(buf), in);
    config = sdscatlen(config, buf, len);
  }

  fclose(in);

  cJSON *json = cJSON_Parse(config);
  if (json == NULL) {
    fprintf(stderr, "Error: Unable to parse E3DB configuration file.\n");
    exit(1);
  }

  E3DB_ClientOptions *opts = E3DB_ClientOptions_New();

  E3DB_ClientOptions_SetApiKey    (opts, get_config_value(json, "api_key_id" )->valuestring);
  E3DB_ClientOptions_SetApiSecret (opts, get_config_value(json, "api_secret" )->valuestring);
  E3DB_ClientOptions_SetClientId  (opts, get_config_value(json, "client_id"  )->valuestring);
  E3DB_ClientOptions_SetPublicKey (opts, get_config_value(json, "public_key" )->valuestring);
  E3DB_ClientOptions_SetPrivateKey(opts, get_config_value(json, "private_key")->valuestring);

  sdsfree(config);
  cJSON_Delete(json);

  return opts;
}

int do_list_records(E3DB_Client *client, int argc, char **argv)
{
  // TODO: Parse command-specific options.

  curl_global_init(CURL_GLOBAL_DEFAULT);

  E3DB_QueryOptions options;
  E3DB_QueryOptions_SetDefault(&options);

  options.include_all_writers = 1;
  options.include_data = 1;

  E3DB_Op *op;

  printf("%-40s %s\n", "Record ID", "Type");
  printf("--------------------------------------------------------------------------------------------------------\n");

  for (;;) {
    op = E3DB_Query_Begin(client, &options);
    curl_run_op(op);

    E3DB_QueryResult *result = E3DB_Query_GetResult(op);

    int count      = E3DB_QueryResult_GetCount(result);
    int last_index = E3DB_QueryResult_GetLastIndex(result);

    if (count != 0) {
      E3DB_QueryResultIterator *it = E3DB_QueryResult_GetIterator(result);

      while (!E3DB_QueryResultIterator_IsDone(it)) {
        E3DB_RecordMeta *meta = E3DB_QueryResultIterator_GetMeta(it);
        printf("%-40s %s\n", E3DB_RecordMeta_GetRecordId(meta), E3DB_RecordMeta_GetType(meta));
        E3DB_QueryResultIterator_Next(it);
      }

      E3DB_QueryResultIterator_Delete(it);
    }

    if (count < options.page_size)
      break;

    options.after_index = last_index;   // get next page
  }

  E3DB_Op_Delete(op);
  curl_global_cleanup();

  return 0;
}

int do_read_records(E3DB_Client *client, int argc, char **argv)
{
  if (argc < 2) {
    fputs(
      "Usage: e3db read [OPTIONS] RECORD_ID...\n"
      "Read one or more records from E3DB.\n"
      "\n"
      "Available options:\n"
      "  -h, --help           print this help and exit\n",
      stderr);
    return 1;
  }

  // TODO: Parse command-specific options.

  curl_global_init(CURL_GLOBAL_DEFAULT);

  E3DB_QueryOptions options;
  E3DB_QueryOptions_SetDefault(&options);

  options.include_all_writers = 1;
  options.include_data = 1;
  options.record_ids = (const char **)&argv[1];
  options.num_record_ids = argc - 1;

  E3DB_Op *op;

  for (;;) {
    op = E3DB_Query_Begin(client, &options);
    curl_run_op(op);

    E3DB_QueryResult *result = E3DB_Query_GetResult(op);

    int count      = E3DB_QueryResult_GetCount(result);
    int last_index = E3DB_QueryResult_GetLastIndex(result);

    if (count != 0) {
      E3DB_QueryResultIterator *it = E3DB_QueryResult_GetIterator(result);

      while (!E3DB_QueryResultIterator_IsDone(it)) {
        E3DB_RecordMeta *meta = E3DB_QueryResultIterator_GetMeta(it);
        E3DB_Record *record   = E3DB_QueryResultIterator_GetData(it);

        printf("\n%-20s %s\n", "record_id", E3DB_RecordMeta_GetRecordId(meta));

        E3DB_RecordFieldIterator *f_it = E3DB_Record_GetFieldIterator(record);

        while (!E3DB_RecordFieldIterator_IsDone(f_it)) {
          printf("%-20s %s\n",
            E3DB_RecordFieldIterator_GetName(f_it),
            E3DB_RecordFieldIterator_GetValue(f_it));
          E3DB_RecordFieldIterator_Next(f_it);
        }

        E3DB_RecordFieldIterator_Delete(f_it);
        E3DB_QueryResultIterator_Next(it);
      }

      E3DB_QueryResultIterator_Delete(it);
    }

    if (count < options.page_size)
      break;

    options.after_index = last_index;   // get next page
  }

  E3DB_Op_Delete(op);
  curl_global_cleanup();

  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    fputs(usage, stderr);
    return 1;
  }

  // TODO: Parse global options.

  E3DB_Client *client = E3DB_Client_New(load_config());

  if (!strcmp(argv[1], "ls")) {
    return do_list_records(client, argc - 1, &argv[1]);
  } else if (!strcmp(argv[1], "read")) {
    return do_read_records(client, argc - 1, &argv[1]);
  } else {
    fputs(usage, stderr);
    return 1;
  }

  E3DB_Client_Delete(client);
}
