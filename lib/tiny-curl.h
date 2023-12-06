/*
 * tiny-curl.h
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#ifndef TINY_CURL_H_INCLUDED
#define TINY_CURL_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include "e3db_core.h"
#include <tiny-curl/curl.h>

	/*
	 * Run a Curl Operation, fail if response code is not 200
	 */
	int curl_run_op(E3DB_Op *op);

	/*
	 * Run a Curl Operation, fail if response code is not expected response code
	 */
	int curl_run_op_with_expected_response_code(E3DB_Op *op, long expected_response_code);

#ifdef __cplusplus
}
#endif

#endif /* !defined TINY_CURL_H_INCLUDED */
