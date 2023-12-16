/*
 * curl.h
 *
 * Copyright (C) 2017-2023, Tozny.
 * All Rights Reserved.
 */

#ifndef CURL_H_INCLUDED
#define CURL_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include "e3db_core.h"

	/*
	 * Run a Curl Operation, fail if response code is not 200
	 */
	int mbedtls_run_op(E3DB_Op *op);

	// int mbedtls_run_op_with_expected_response_code(E3DB_Op *op);

	/*
	 * Run a Curl Operation, fail if response code is not expected response code
	 */
	int curl_run_op_with_expected_response_code(E3DB_Op *op, long expected_response_code);

#ifdef __cplusplus
}
#endif

#endif /* !defined CURL_H_INCLUDED */
