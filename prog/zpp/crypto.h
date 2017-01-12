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
/**
 * These functions provide functionality as follows:
 * - encrypt/decrypt a certain buffer
 * - initialize the crypto stuff (generating key or reading key)
 **/

#ifndef _CRYPTO_BASE_H_
#define _CRYPTO_BASE_H_

#include <sgx_tcrypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "zookeeper.jute.h"
#include "Enclave.h"
#include "base64.h"

#define MACLEN 16
#define HASHLEN 32
#define IVLEN 12

extern const sgx_aes_gcm_128bit_key_t aes_key[16];

#ifdef __cplusplus
extern "C" {
#endif

int get_overhead_with_nonce();
void crypto_init();
int encrypt_buffer(package_t * p_package);
int decrypt_buffer(package_t * p_package);
char* sgx_decrypt_rijndael(char* cipher, size_t* size);
char* sgx_encrypt_rijndael(char* plain, size_t* size);


/**
 * This functions decrypts the metadata of a node,
 * it decreases the dataLen stated.
 **/
void decrypt_metadata(struct Stat * stat);

/**
 * This functions encrypts the payload of path 
 * stored in a buffer of size *sizeP \
 * pointed to by payloadP.
 * *payloadP is freed, and then a new buffer which size is stored in *sizeP 
 * is allocated. Afterwards the encrypted payload is stored there.
 **/
int encrypt_payload(char ** p_buffer, int * p_size, char * path);

/**
 * This functions decrypts the payload stored in a buffer of size *sizeP \
 * pointed to by payloadP.
 * *payloadP is freed, and then a new buffer which size is stored in *sizeP 
 * is allocated. Afterwards the decrypted payload is stored there.
 **/
int decrypt_payload(char ** p_buffer, int * p_size, char * path);

int path_decryption(const char* cipher_path, const size_t cipher_path_len, char** ret_path, size_t* ret_len);
int path_encryption(const char* path, const size_t path_len, char** ret_path, size_t* ret_len);
char* decrypt_chunk(const char* chunk, size_t* length);
//not required to be public: char* encrypt_chunk(const char* chunk, size_t* clen, const char* fullpath, const size_t fplen);
void encrypt_path(char** path);
void decrypt_path(char** cipherpath);
void decrypt_nodename(char **nodename);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTO_BASE_H_ */
