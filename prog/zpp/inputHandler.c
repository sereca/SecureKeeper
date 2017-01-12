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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "inputHandler.h"
#include "crypto.h"
#include "requestHandler.h"
#include "responseHandler.h"
#include "operationCodes.h"
#include "list.h"
#include "utils.h"
#include "debugflag.h"
#include "byte_order_conversion.h"
#include "Enclave.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

static list_t list = { NULL, NULL };

int handle_buffer(package_t * p_package, sender_t sender) {
	int package_changed = 0;
	int xid = ntohl(*(int*)(p_package->buffer));

	// ignore heartbeats
	if (xid == -2) {
		if (sender == CLIENT) {
#if defined(PING) || defined(DEMO)
			printf("%s### ping()...%s\n", KWHT, KNRM);
#endif
		}
		return package_changed;
	}

	// ignore connection establishment
	if (xid == 0) {
#if defined(DEBUG) || defined(DEMO)
		printf("%sConnection establishment...%s\n", KWHT, KNRM);
#endif
		return package_changed;
	}

	if (sender == CLIENT) {
		package_changed = handle_request(p_package, &list);
	} else { //ZOOKEEPER
		package_changed = handle_response(p_package, &list);
	}

	return package_changed;
}

#ifdef __cplusplus
extern "C" {
#endif

// Request: encrypted package from client arrives in enclave for zookeeper
size_t ecall_handle_input_from_client(char * buffer, size_t psize, size_t buffersize, int eid) {
	char* plain;
#if defined(ENCLAVE_TRANSITION) || defined(REQRES) || defined(DEMO)
	printf("\n%sENCLAVE(ID=%d) START: request size %d.%s\n", KRED, eid, psize, KNRM);
#endif

	size_t oldsize = psize;
	size_t newsize = psize;

#if defined(DEMO)
	printf("Decrypting incoming buffer (%d Bytes)...\n", psize);
#endif
	// decrypt reduces length by MACLEN Byte MAC (!)
	plain = sgx_decrypt_rijndael(buffer, &newsize);

#if defined(DEMO)
	hexdump("buffer (encrypted)", buffer, newsize > 128 ? 128 : newsize);
	hexdump("buffer (decrypted)", plain, newsize > 128 ? 128 : newsize);
#endif

	package_t pack;
	pack.buffer = buffer;
	memcpy(buffer, plain, newsize);
	pack.size = newsize;
	handle_buffer(&pack, CLIENT);

#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, plain);
#endif
	free(plain);

#if defined(ENCLAVE_TRANSITION) || defined(DEMO)
	printf("%sENCLAVE END: request size %d.%s\n\n", KRED, pack.size, KNRM);
#endif

	return pack.size;
}

// Response: payload-encrypted package from zookeeper arrives in enclave for client
size_t ecall_handle_input_from_zookeeper(char * buffer, size_t psize, size_t buffersize, int eid) {

#if defined(ENCLAVE_TRANSITION) || defined(REQRES) || defined(DEMO)
	printf("\n%sENCLAVE(ID=%d) START: response size %d. %s\n", KRED, eid, psize, KNRM);
#endif

	size_t oldsize = psize;

	package_t pack;
	pack.buffer = buffer;
	pack.size = psize;

	handle_buffer(&pack, ZOOKEEPER);

	if (pack.size < 0) {
		printf("%s:%s:%d: invalid size, %d.\n", pack.size);
		return 0;
	}

#if defined(DEMO)
	printf("Encrypting outgoing buffer (%d Bytes)...\n", psize);
	hexdump("buffer (unencrypted)", pack.buffer, pack.size > 128 ? 128 : pack.size);
#endif
	// encrypt increases length by 16 Byte MAC (!)
	char* cipher = sgx_encrypt_rijndael(pack.buffer, &pack.size);
#if defined(DEMO)
	hexdump("buffer (encrypted)", cipher, pack.size > 128 ? 128 : pack.size);
#endif

	if (pack.size < 0 || pack.size > buffersize) {
		printf("%s:%s:%d: invalid size, %d, buffersize=%d.\n", __FILE__, __FUNCTION__, __LINE__, pack.size, buffersize);
		return 0;
	}
	memcpy(buffer, cipher, pack.size);

#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, cipher);
#endif
	free(cipher);

#if defined(ENCLAVE_TRANSITION) || defined(DEMO)
	printf("%sENCLAVE END: response size %d.%s\n\n", KRED, pack.size, KNRM);
#endif
	return pack.size;
}

#ifdef __cplusplus
}
#endif

