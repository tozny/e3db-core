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
#include <openssl/evp.h>

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
    " read-record          read records\n"
    " write                write record\n"
    " writeFile            write file\n";

int calcDecodeLength(const char *b64input)
{ // Calculates the length of a decoded base64 string
  int len = strlen(b64input);
  int padding = 0;

  if (b64input[len - 1] == '=' && b64input[len - 2] == '=') // last two chars are =
    padding = 2;
  else if (b64input[len - 1] == '=') // last char is =
    padding = 1;

  return (int)len * 0.75 - padding;
}

char *base64_decode1(const char *s)
{
  BIO *bio, *b64;
  int decodeLen = (strlen(s) / 4) * 3;
  char *buffer = (char *)malloc(decodeLen + 1); // +1 for the null terminator
  if (buffer == NULL)
  {
    fprintf(stderr, "Memory allocation failed\n");
    return NULL;
  }

  memset(buffer, 0, decodeLen + 1); // Initialize buffer to zeros

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(s, -1); // -1 indicates string is null terminated
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Don't require newlines

  int bytesRead = BIO_read(bio, buffer, decodeLen);
  if (bytesRead < 0)
  {
    fprintf(stderr, "BIO_read failed\n");
    free(buffer);
    BIO_free_all(bio);
    return NULL;
  }

  buffer[bytesRead] = '\0'; // Null-terminate the result

  return buffer;
  // sds result = sdsnewlen(buffer, bytesRead); // Create sds string with the correct length

  // free(buffer);
  // BIO_free_all(bio);

  // return result;
}

/* Callback function for libcurl to write data received from an HTTP
 * request to an OpenSSL BIO. Returns the number of bytes written. */
size_t write_body(void *ptr, size_t size, size_t nmemb, BIO *bio)
{
  size_t len = size * nmemb;
  int result;

  if ((result = BIO_write(bio, ptr, len)) < 0)
  {
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

  if ((result = BIO_read(bio, ptr, len)) < 0)
  {
    fprintf(stderr, "read_body: BIO_read failed\n");
    abort();
  }

  return (size_t)result;
}

/* Complete an E3DB operation using libcurl for HTTP requests. */
int curl_run_op(E3DB_Op *op)
{
  CURL *curl;

  if ((curl = curl_easy_init()) == NULL)
  {
    fprintf(stderr, "Fatal: Curl initialization failed.\n");
    exit(1);
  }

  while (!E3DB_Op_IsDone(op))
  {
    if (E3DB_Op_IsHttpState(op))
    {
      curl_easy_reset(curl);

      const char *method = E3DB_Op_GetHttpMethod(op);
      E3DB_HttpHeaderList *headers = E3DB_Op_GetHttpHeaders(op);
      BIO *write_bio = BIO_new(BIO_s_mem());

      struct curl_slist *chunk = NULL;
      E3DB_HttpHeader *header = E3DB_HttpHeaderList_GetFirst(headers);

      while (header != NULL)
      {
        sds header_text = sdscatprintf(sdsempty(), "%s: %s",
                                       E3DB_HttpHeader_GetName(header), E3DB_HttpHeader_GetValue(header));
        chunk = curl_slist_append(chunk, header_text);
        sdsfree(header_text);

        header = E3DB_HttpHeader_GetNext(header);
      }

      if (!strcmp(method, "POST"))
      {
        const char *post_body = E3DB_Op_GetHttpBody(op);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
      }
      else if (!strcmp(method, "GET"))
      {
        // nothing special for GET
      }
      else
      {
        fprintf(stderr, "Unsupported method: %s\n", method);
        abort();
      }

      curl_easy_setopt(curl, CURLOPT_URL, E3DB_Op_GetHttpUrl(op));
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_bio);

      CURLcode res = curl_easy_perform(curl);
      if (res != CURLE_OK)
      {
        fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
      }

      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

      char *body;
      BIO_write(write_bio, "\0", 1);
      BIO_get_mem_data(write_bio, &body);
      E3DB_Op_FinishHttpState(op, response_code, body, NULL, 0);
      printf("Response Code %ld", response_code);
      printf("HELLOO %s", body);
      BIO_free_all(write_bio);
      curl_slist_free_all(chunk);
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

  if ((home = getenv("HOME")) != NULL)
  {
    return sdsnew(home);
  }

  uid_t uid = getuid();
  struct passwd *pw = getpwuid(uid);

  if (pw == NULL)
  {
    fprintf(stderr, "Error: Unable to get user home directory.\n");
    exit(1);
  }

  return sdsnew(pw->pw_dir);
}

/* Load the user's e3db configuration into an E3DB_ClientOptions. */
E3DB_ClientOptions *load_config(void)
{

  sds config_file = sdscat(get_home_dir(), "/.tozny/e3db.json");
  FILE *in;

  if ((in = fopen(config_file, "r")) == NULL)
  {
    fprintf(stderr, "Error: Unable to open E3DB configuration file.\n");
    // TODO: Point the user to a registration flow.
    exit(1);
  }

  sds config = sdsempty();

  while (!feof(in))
  {
    char buf[4096];
    size_t len;

    len = fread(buf, 1, sizeof(buf), in);
    config = sdscatlen(config, buf, len);
  }

  fclose(in);
  cJSON *json = cJSON_Parse(config);
  if (json == NULL)
  {
    fprintf(stderr, "Error: Unable to parse E3DB configuration file.\n");
    exit(1);
  }

  E3DB_ClientOptions *opts = E3DB_ClientOptions_New();
  cJSON *api_key, *api_secret, *client_id, *private_key;

  api_key = cJSON_GetObjectItem(json, "api_key_id");
  if (api_key == NULL || api_key->type != cJSON_String)
  {
    fprintf(stderr, "Error: Missing 'api_key_id' key in configuration file.\n");
    exit(1);
  }

  api_secret = cJSON_GetObjectItem(json, "api_secret");
  if (api_secret == NULL || api_secret->type != cJSON_String)
  {
    fprintf(stderr, "Error: Missing 'api_secret' key in configuration file.\n");
    exit(1);
  }

  client_id = cJSON_GetObjectItem(json, "client_id");
  if (client_id == NULL || client_id->type != cJSON_String)
  {
    fprintf(stderr, "Error: Missing 'client_id' key in configuration file.\n");
    exit(1);
  }

  private_key = cJSON_GetObjectItem(json, "private_key");
  if (private_key == NULL || private_key->type != cJSON_String)
  {
    fprintf(stderr, "Error: Missing 'private_key' key in configuration file.\n");
    exit(1);
  }

  E3DB_ClientOptions_SetApiKey(opts, api_key->valuestring);
  E3DB_ClientOptions_SetApiSecret(opts, api_secret->valuestring);
  E3DB_ClientOptions_SetClientID(opts, client_id->valuestring);
  E3DB_ClientOptions_SetPrivateKey(opts, private_key->valuestring);

  sdsfree(config);
  cJSON_Delete(json);

  return opts;
}

int do_list_records(E3DB_Client *client, int argc, char **argv)
{
  // TODO: Parse command-specific options.

  // curl_global_init(CURL_GLOBAL_DEFAULT);

  E3DB_Op *op = E3DB_ListRecords_Begin(client, 100, 0, NULL, NULL, 0);

  curl_run_op(op);

  E3DB_ListRecordsResult *result = E3DB_ListRecords_GetResult(op);
  E3DB_ListRecordsResultIterator *it = E3DB_ListRecordsResult_GetIterator(result);

  printf("%-40s %-40s %s\n", "Record ID", "Writer ID", "Type");
  printf("--------------------------------------------------------------------------------------------------------\n");

  while (!E3DB_ListRecordsResultIterator_IsDone(it))
  {
    E3DB_RecordMeta *meta = E3DB_ListRecordsResultIterator_Get(it);

    printf("%-40s %-40s %s\n",
           E3DB_RecordMeta_GetRecordId(meta),
           E3DB_RecordMeta_GetWriterId(meta),
           E3DB_RecordMeta_GetType(meta));

    E3DB_ListRecordsResultIterator_Next(it);
  }

  E3DB_ListRecordsResultIterator_Delete(it);
  E3DB_Op_Delete(op);
  curl_global_cleanup();

  return 0;
}

int do_read_records(E3DB_Client *client, int argc, char **argv)
{
  if (argc < 2)
  {
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

  const char **record_ids = (const char **)&argv[1];
  printf("\nRECORDS = %s\n", *record_ids);
  E3DB_Op *op = E3DB_ReadRecords_Begin(client, record_ids, argc - 1, NULL, 0);
  curl_run_op(op);

  E3DB_ReadRecordsResult *result = E3DB_ReadRecords_GetResult(op);
  E3DB_ReadRecordsResultIterator *it = E3DB_ReadRecordsResult_GetIterator(result);

  while (!E3DB_ReadRecordsResultIterator_IsDone(it))
  {
    // At this point we have encrypted data
    E3DB_RecordMeta *meta = E3DB_ReadRecordsResultIterator_GetMeta(it);
    E3DB_Record *record = E3DB_ReadRecordsResultIterator_GetData(it);

    // Set up Access Keys Fetch
    E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, E3DB_RecordMeta_GetWriterId(meta), E3DB_RecordMeta_GetUserId(meta), E3DB_RecordMeta_GetUserId(meta), E3DB_RecordMeta_GetType(meta), NULL, 0);

    // Run access keys fetch
    curl_run_op(op);

    E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(op);
    E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
    E3DB_EAK *eak = E3DB_ReadRecordsResultIterator_GetEAK(EAKIt);
    char *rawEAK = E3DB_EAK_GetEAK(eak);
    char *authPublicKey = E3DB_EAK_GetAuthPubKey(eak);
    //E3DB_ClientOptions *clientOptions = client.;
    unsigned char *ak = E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, "e4Yj6iGbUrJGy3mrxuXXXqmeybyskuxAU48Cx5iFevo");

    printf("\n%-20s %s\n", "record_id", E3DB_RecordMeta_GetRecordId(meta));
    printf("\n%-20s %s\n", "record_type", E3DB_RecordMeta_GetType(meta));

    E3DB_RecordFieldIterator *f_it = E3DB_Record_GetFieldIterator(record);

    while (!E3DB_RecordFieldIterator_IsDone(f_it))
    {
      unsigned char *edata = E3DB_RecordFieldIterator_GetValue(f_it);
      char *data = E3DB_RecordFieldIterator_DecryptValue(edata, ak);

      printf("\n %-20s %s\n",
             E3DB_RecordFieldIterator_GetName(f_it),
             data);
      free(data);
      E3DB_RecordFieldIterator_Next(f_it);
    }
    free(ak);
    E3DB_RecordFieldIterator_Delete(f_it);
    E3DB_ReadRecordsResultIterator_Next(it);
  }

  E3DB_ReadRecordsResultIterator_Delete(it);
  E3DB_Op_Delete(op);
  curl_global_cleanup();

  return 0;
}

int do_write_record(E3DB_Client *client, int argc, char **argv)
{
  printf("%s", argv);
  if (argc < 2)
  {
    fputs(
        "Usage: e3db write [OPTIONS] -t TYPE -d  DATA -m META \n"
        "Write a record to E3DB.\n"
        "Pass in as JSON"
        "\n"
        "Available options:\n"
        "  -h, --help           print this help and exit\n",
        stderr);
    return 1;
  }

  // printf("%s", argv);
  // ./build/e3db write -t record-type -d "data" -m "meta"

  // Get Type
  const char **record_type = (const char **)&argv[2];
  // Get Data
  const char **data = (const char **)&argv[4];
  // Get Meta Data
  const char **meta = (const char **)&argv[6];

  curl_global_init(CURL_GLOBAL_DEFAULT);
  printf("Before record begin");
  E3DB_Op *op = E3DB_WriteRecord_Begin(client, record_type, data, meta);
  printf("after record begin");

  curl_run_op(op);

  E3DB_WriteRecordsResult *result = E3DB_WriteRecords_GetResult(op);

  E3DB_Op_Delete(op);
  curl_global_cleanup();

  return 0;
}

int main(int argc, char **argv)
{

  printf("e3db-cli\n");
  printf("E3DB Command Line Interface\n");
  printf("Instructions: \n");
  printf("You must have a configuration file here: /.tozny/e3db.json\n");
  printf("HELLOOO");
  // Catches the help option
  if (argc < 2)
  {
    fputs(usage, stderr);
    return 1;
  }
  printf("HELLOOO");
  printf("%s", &argv[1]);

  E3DB_Client *client = E3DB_Client_New(load_config());

  if (!strcmp(argv[1], "read-record"))
  {
    return do_read_records(client, argc - 1, &argv[1]);
  }
  else if (!strcmp(argv[1], "write"))
  {
    return do_write_record(client, argc - 1, &argv);
  }
  else
  {
    fputs(usage, stderr);
    return 1;
  }

  E3DB_Client_Delete(client);
}
