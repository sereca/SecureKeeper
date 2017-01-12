/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Stefan Brenner, Colin Wulf
 */
/*
 This file is based on base64 encode/decode code from
 https://github.com/algermissen/hawkc/blob/master/hawkc/base64url.c
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int base64url_encode(const unsigned char* data, size_t data_len,
		unsigned char *result, size_t *result_len);
int base64url_decode(const unsigned char* data, size_t data_len,
		unsigned char *result, size_t *result_len);

int base64url_encode_len(const size_t data_len);
int base64url_decode_len(const size_t data_len);

#ifdef __cplusplus
}
#endif

#endif
