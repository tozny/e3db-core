/*
 * e3db_core.h
 *
 * Copyright (C) 2017, Tozny, LLC.
 * All Rights Reserved.
 */

#ifndef E3DB_CLIENT_H_INCLUDED
#define E3DB_CLIENT_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h> // for size_t
	/*
	 * {Client Options}
	 */

	typedef struct _E3DB_ClientOptions E3DB_ClientOptions;

	E3DB_ClientOptions *E3DB_ClientOptions_New(void);
	void E3DB_ClientOptions_Delete(E3DB_ClientOptions *opts);

	void E3DB_ClientOptions_SetApiUrl(E3DB_ClientOptions *opts, const char *url);
	void E3DB_ClientOptions_SetApiKey(E3DB_ClientOptions *opts, const char *api_key);
	void E3DB_ClientOptions_SetApiSecret(E3DB_ClientOptions *opts, const char *api_secret);
	void E3DB_ClientOptions_SetClientID(E3DB_ClientOptions *opts, const char *client_id);
	void E3DB_ClientOptions_SetPrivateKey(E3DB_ClientOptions *opts, const char *private_key);
	void E3DB_ClientOptions_SetPublicKey(E3DB_ClientOptions *opts, const char *public_key);

	/*
	 * {Clients}
	 */

	typedef struct _E3DB_Client E3DB_Client;

	/* Create an E3DB client object given a set of options.  The newly created
	 * client assumes ownership of `opts', so it does not need to be freed. */
	E3DB_Client *E3DB_Client_New(E3DB_ClientOptions *opts);

	/* Free an E3DB client object. */
	void E3DB_Client_Delete(E3DB_Client *client);

#ifdef __cplusplus
}
#endif

#endif /* !defined E3DB_CLIENT_H_INCLUDED */
