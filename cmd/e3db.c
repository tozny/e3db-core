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
#include "e3db_core.c"
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
    " write-record                write record\n";

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
  printf("\n%s\n", "Top");
  CURL *curl;

  if ((curl = curl_easy_init()) == NULL)
  {
    printf("%s", "IF");
    fprintf(stderr, "Fatal: Curl initialization failed.\n");
    exit(1);
  }

  while (!E3DB_Op_IsDone(op))
  {
    printf("%s", "While");
    if (E3DB_Op_IsHttpState(op))
    {
      printf("%s", "If inside While");
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
        printf("%s", "IF POST");
        const char *post_body = E3DB_Op_GetHttpBody(op);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
      }
      else if (!strcmp(method, "GET"))
      {
        // nothing special for GET
      }
      else if (!strcmp(method, "PUT"))
      {
        const char *put_body = E3DB_Op_GetHttpBody(op);
        printf("bBODYYY %s \n \n \n ", put_body);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, put_body);
      }
      else
      {
        fprintf(stderr, "Unsupported method: %s\n", method);
        abort();
      }
      printf("in Curl Op before perform %s", "before");
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
      printf("in Curl Op after perform %s", "After");
      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

      char *body;
      BIO_write(write_bio, "\0", 1);
      BIO_get_mem_data(write_bio, &body);
      E3DB_Op_FinishHttpState(op, response_code, body, NULL, 0);
      printf("\nHELLOO %s\n", body);
      BIO_free_all(write_bio);
      curl_slist_free_all(chunk);
    }
  }

  curl_easy_cleanup(curl);
  return 0;
}

/* Complete an E3DB operation using libcurl for HTTP requests. */
int curl_run_op_dont_fail_with_response_code(E3DB_Op *op, long response_code_not_errored)
{
  printf("%s", "Top");
  CURL *curl;

  if ((curl = curl_easy_init()) == NULL)
  {
    printf("%s", "IF");
    fprintf(stderr, "Fatal: Curl initialization failed.\n");
    exit(1);
  }

  while (!E3DB_Op_IsDone(op))
  {
    printf("%s", "While");
    if (E3DB_Op_IsHttpState(op))
    {
      printf("%s", "If inside While");
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
        printf("%s", "IF POST");
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
      printf("in Curl Op before perform %s", "before");
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
      printf("in Curl Op after perform %s", "After");
      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      printf("RESPONSE CODE %ld", response_code);
      if (response_code == response_code_not_errored)
      {
        curl_easy_cleanup(curl);
        return response_code_not_errored;
      }

      char *body;
      BIO_write(write_bio, "\0", 1);
      BIO_get_mem_data(write_bio, &body);
      E3DB_Op_FinishHttpState(op, response_code, body, NULL, 0);
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
  cJSON *api_key, *api_secret, *client_id, *private_key, *public_key, *private_signing_key;

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

  public_key = cJSON_GetObjectItem(json, "public_key");
  if (public_key == NULL || public_key->type != cJSON_String)
  {
    fprintf(stderr, "Error: Missing 'public_key' key in configuration file.\n");
    exit(1);
  }

  private_signing_key = cJSON_GetObjectItem(json, "private_signing_key");
  if (private_signing_key == NULL || private_signing_key->type != cJSON_String)
  {
    fprintf(stderr, "Error: Missing 'private_signing_key' key in configuration file.\n");
    exit(1);
  }

  E3DB_ClientOptions_SetApiKey(opts, api_key->valuestring);
  E3DB_ClientOptions_SetApiSecret(opts, api_secret->valuestring);
  E3DB_ClientOptions_SetClientID(opts, client_id->valuestring);
  E3DB_ClientOptions_SetPrivateKey(opts, private_key->valuestring);
  E3DB_ClientOptions_SetPublicKey(opts, public_key->valuestring);
  E3DB_ClientOptions_SetPrivateSigningKey(opts, private_signing_key->valuestring);

  sdsfree(config_file);
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

  const char **all_record_ids = (const char **)&argv[1];
  E3DB_DecryptedRecord *decrypted_records = (E3DB_DecryptedRecord *)malloc(sizeof(E3DB_DecryptedRecord) * (argc - 1));

  for (int i = 0; i < argc - 1; i++)
  {
    const char **record_ids = (const char **)malloc(sizeof(const char *));
    record_ids[0] = all_record_ids[i];

    E3DB_Op *op = E3DB_ReadRecords_Begin(client, &all_record_ids[i], 1, NULL, 0);
    curl_run_op(op);

    E3DB_ReadRecordsResult *result = E3DB_ReadRecords_GetResult(op);
    E3DB_ReadRecordsResultIterator *it = E3DB_ReadRecordsResult_GetIterator(result);
    while (!E3DB_ReadRecordsResultIterator_IsDone(it))
    {
      // At this point we have encrypted data
      E3DB_RecordMeta *meta = E3DB_ReadRecordsResultIterator_GetMeta(it);
      E3DB_Record *record = E3DB_ReadRecordsResultIterator_GetData(it);

      // Set up Access Keys Fetch
      E3DB_Op *eakOp = E3DB_GetEncryptedAccessKeys_Begin(client, E3DB_RecordMeta_GetWriterId(meta), E3DB_RecordMeta_GetUserId(meta), E3DB_RecordMeta_GetUserId(meta), E3DB_RecordMeta_GetType(meta));

      // Run access keys fetch
      curl_run_op(eakOp);

      E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(eakOp);
      E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
      E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
      char *rawEAK = E3DB_EAK_GetEAK(eak);
      char *authPublicKey = E3DB_EAK_GetAuthPubKey(eak);
      unsigned char *ak = E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, eakOp->client->options->private_key);

      E3DB_DecryptedRecord *decrypted_record = (E3DB_DecryptedRecord *)malloc(sizeof(E3DB_DecryptedRecord));
      decrypted_record->meta = meta;
      decrypted_record->rec_sig = E3DB_ReadRecordsResultIterator_GetRecSig(it);

      // Decrypt the record data
      E3DB_RecordFieldIterator *f_it = E3DB_Record_GetFieldIterator(record);
      cJSON *decryptedData = cJSON_CreateObject();
      while (!E3DB_RecordFieldIterator_IsDone(f_it))
      {
        unsigned char *edata = E3DB_RecordFieldIterator_GetValue(f_it);

        char *ddata = E3DB_RecordFieldIterator_DecryptValue(edata, ak);
        char *name = E3DB_RecordFieldIterator_GetName(f_it);

        cJSON_AddStringToObject(decryptedData, name, ddata);

        free(ddata);
        E3DB_RecordFieldIterator_Next(f_it);
      }
      decrypted_record->data = decryptedData;

      decrypted_records[i] = *decrypted_record;

      // Print the record info
      printf("\nRECORD INFO FOR RECORD #%d:\n", i + 1);
      printf("\n%-20s %s\n", "record_id:", decrypted_records[i].meta->record_id);
      printf("\n%-20s %s\n", "record_type:", decrypted_records[i].meta->type);
      printf("\n%-20s %s\n", "writer_id:", decrypted_records[i].meta->writer_id);
      printf("\n%-20s %s\n", "user_id:", decrypted_records[i].meta->user_id);
      printf("\n%-20s %s\n", "version:", decrypted_records[i].meta->version);
      printf("\n%-20s %s\n", "created:", decrypted_records[i].meta->created);
      printf("\n%-20s %s\n", "last_modified:", decrypted_records[i].meta->last_modified);
      printf("\n%-20s %s\n", "rec_sig:", decrypted_records[i].rec_sig);
      printf("\n%-20s \n%s\n", "plain:", cJSON_Print(decrypted_records[i].meta->plain));
      printf("\n%-20s \n%s\n", "data:", cJSON_Print(decrypted_records[i].data));

      // Free all memory
      // TODO move all memory freeing to a separate function for each object
      // free(ak);

      // if (EAKIt)
      // {
      //   if (EAKIt->pos)
      //     cJSON_Delete(EAKIt->pos);
      //   free(EAKIt);
      // }

      // if (decrypted_record)
      // {
      //   if (decrypted_record->data)
      //     cJSON_Delete(decrypted_record->data);
      //   if (decrypted_record->rec_sig)
      //     free(decrypted_record->rec_sig);
      //   if (decrypted_record->meta)
      //   {
      //     if (decrypted_record->meta->record_id)
      //       free(decrypted_record->meta->record_id);
      //     if (decrypted_record->meta->writer_id)
      //       free(decrypted_record->meta->writer_id);
      //     if (decrypted_record->meta->user_id)
      //       free(decrypted_record->meta->user_id);
      //     if (decrypted_record->meta->type)
      //       free(decrypted_record->meta->type);
      //     if (decrypted_record->meta->version)
      //       free(decrypted_record->meta->version);
      //     if (decrypted_record->meta->last_modified)
      //       free(decrypted_record->meta->last_modified);
      //     if (decrypted_record->meta->created)
      //       free(decrypted_record->meta->created);
      //     if (decrypted_record->meta->plain)
      //       cJSON_Delete(decrypted_record->meta->plain);
      //     free(decrypted_record->meta);
      //   }
      // }

      // if (eak)
      // {
      //   if (eak->eak)
      //     free(eak->eak);
      //   if (eak->signer_id)
      //     free(eak->signer_id);
      //   if (eak->authorizer_id)
      //     free(eak->authorizer_id);
      //   if (eak->signer_signing_key.ed25519)
      //     free(eak->signer_signing_key.ed25519);
      //   if (eak->auth_pub_key.curve25519)
      //     free(eak->auth_pub_key.curve25519);
      //   free(eak);
      // }
      E3DB_RecordFieldIterator_Delete(f_it);
      E3DB_ReadRecordsResultIterator_Next(it);
    }

    E3DB_ReadRecordsResultIterator_Delete(it);
    E3DB_Op_Delete(op);
    curl_global_cleanup();
  }

  return 0;
}

int do_write_record(E3DB_Client *client, int argc, char **argv)
{
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

  const char *record_type = NULL;
  const char *data = NULL;
  const char *meta = NULL;

  for (int i = 1; i <= argc; i++)
  {
    if (strcmp(argv[i], "-t") == 0)
    {
      if (i + 1 <= argc && argv[i + 1][0] != '-')
      {
        record_type = argv[i + 1];
      }
    }
    else if (strcmp(argv[i], "-d") == 0)
    {
      if (i + 1 <= argc && argv[i + 1][0] != '-')
      {
        data = argv[i + 1];
      }
    }
    else if (strcmp(argv[i], "-m") == 0)
    {
      if (i + 1 <= argc && argv[i + 1][0] != '-')
      {
        meta = argv[i + 1];
      }
    }
  }

  if (record_type == NULL || data == NULL || meta == NULL)
  {
    printf("Record Type(-t) or Meta(-m) or Data(-d) are not provided.\n");
    return 0;
  }
  printf("Data Type %s\n", data);
  printf("Meta Type %s\n", meta);

  // Set Up Curl to be used
  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Step 1: Get Access Key
  E3DB_Op *op = E3DB_GetEncryptedAccessKeys_Begin(client, client->options->client_id, client->options->client_id, client->options->client_id, record_type);

  int responseCode = curl_run_op_dont_fail_with_response_code(op, 404);

  if (responseCode == 404)
  {
    // Path B: Access Key Does Not Exist
    // Create Access Key
    E3DB_Op *operationCreateAccessKey = E3DB_CreateAccessKeys_Begin(client, client->options->client_id, client->options->client_id, client->options->client_id, record_type, client->options->public_key);
    curl_run_op(operationCreateAccessKey);
    // Fetch Encrypted Access Key
    op = E3DB_GetEncryptedAccessKeys_Begin(client, client->options->client_id, client->options->client_id, client->options->client_id, record_type);
    curl_run_op(op);
  }

  // Step 2: Decrypt Access Key
  E3DB_EncryptedAccessKeyResult *EAKResult = E3DB_EAK_GetResult(op);
  E3DB_GetEAKResultIterator *EAKIt = E3DB_GetEAKResultIterator_GetIterator(EAKResult);
  E3DB_EAK *eak = E3DB_ResultIterator_GetEAK(EAKIt);
  char *rawEAK = E3DB_EAK_GetEAK(eak);
  char *authPublicKey = E3DB_EAK_GetAuthPubKey(eak);
  unsigned char *ak = E3DB_EAK_DecryptEAK(rawEAK, authPublicKey, op->client->options->private_key);

  // Write Record
  op = E3DB_WriteRecord_Begin(client, record_type, data, meta, ak);
  curl_run_op(op);

  // Get Results
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
  // Catches the help option
  if (argc < 2)
  {
    fputs(usage, stderr);
    return 1;
  }

  E3DB_Client *client = E3DB_Client_New(load_config());

  if (!strcmp(argv[1], "read-record"))
  {
    int records_read = do_read_records(client, argc - 1, &argv[1]);
    E3DB_Client_Delete(client);
    return records_read;
  }
  else if (!strcmp(argv[1], "write-record"))
  {
    int records_written = do_write_record(client, argc - 1, argv);
    E3DB_Client_Delete(client);
    return records_written;
  }
  else
  {
    fputs(usage, stderr);
    E3DB_Client_Delete(client);
    return 1;
  }
}
