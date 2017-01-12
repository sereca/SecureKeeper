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
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "org_apache_zookeeper_server_Zpp.h"
#include "zpp/utils.h"
#include "zpp/debugflag.h"
#include "Enclave_u.h"
#include "App.h"

int printSgxStatus(sgx_status_t status) {
	switch (status) {
	case SGX_SUCCESS:
#ifdef DEBUG
		printf("sgx status code: SGX_SUCCESS.\n");
#endif
		break;
	case SGX_ERROR_INVALID_PARAMETER:
		printf("sgx status code: SGX_ERROR_INVALID_PARAMETER.\n");
		break;
	case SGX_ERROR_OUT_OF_MEMORY:
		printf("sgx status code: SGX_ERROR_OUT_OF_MEMORY.\n");
		return 1;
	case SGX_ERROR_UNEXPECTED:
		printf("sgx status code: SGX_ERROR_UNEXPECTED.\n");
		break;
	case SGX_ERROR_MAC_MISMATCH:
		printf("sgx status code: SGX_ERROR_MAC_MISMATCH.\n");
		break;
	case SGX_ERROR_OUT_OF_TCS:
		printf("sgx status code: SGX_ERROR_OUT_OF_TCS.\n");
		break;
	case SGX_ERROR_ENCLAVE_CRASHED:
		printf("sgx status code: SGX_ERROR_ENCLAVE_CRASHED.\n");
		break;
	default:
		printf("sgx status code: Unknown status code (%X).\n", (int) status);
	}
	return 0;
}

JNIEXPORT jlong JNICALL Java_org_apache_zookeeper_server_Zpp_initEnclave(JNIEnv *env, jobject obj) {
	long eid = enclave_init();
	if (eid < 0) {
		printf("error during enclave init, eid=%ld.\n", eid);
		abort();
	}
	return (jlong) eid;
}

// Requests go into this JNI call
JNIEXPORT jbyteArray JNICALL Java_org_apache_zookeeper_server_Zpp_requestIntoZpp(JNIEnv *env, jobject thisClass,
		jbyteArray array, jlong enclaveid) {
	jbyteArray result;
	static int requests = 0;

	jsize jArraySize = (*env)->GetArrayLength(env, array);

	jbyte* buf = (*env)->GetByteArrayElements(env, array, 0);
	size_t buffersize = jArraySize * 2 < 256 ? 256 : jArraySize * 2; // double the size, min 64 bytes.
	char * buffer = (char*)malloc(buffersize);
#ifdef CAPTURE
	memset(buffer,0,buffersize);
#endif
	memcpy(buffer, buf, jArraySize);
//	free(buf);

retryEnter1: ;
	int returnValue;
	size_t psize = jArraySize;

#ifdef CAPTURE
	printf("Enclave request: len %d\n", (int)psize);
	hexdump_clean("buffer", buffer, buffersize);
#endif

	sgx_status_t ret = ecall_handle_input_from_client(enclaveid, &psize, buffer, psize, buffersize, (int) enclaveid);
	if (ret != SGX_SUCCESS) {
		if(ret == SGX_ERROR_OUT_OF_TCS) {
			sleep(1);
			goto retryEnter1;
		}
		printf("Error: Something wrong with handle input from client ecall(%X), eid=%ld, requests=%d.\n", (int) ret, enclaveid, requests);
		printSgxStatus(ret);
		abort();
	}
	requests++;

	// we need a new array because output might be larger than input
	result = (*env)->NewByteArray(env, psize);
	(*env)->SetByteArrayRegion(env, result, 0, psize, buffer);

	// write back the changes made to "buffer" into the java "array"
	(*env)->ReleaseByteArrayElements(env, array, buf, 0);

	free(buffer);

	return result;
}

// Responses go into this JNI call
JNIEXPORT jbyteArray JNICALL Java_org_apache_zookeeper_server_Zpp_responseIntoZpp(JNIEnv *env, jobject thisClass,
		jbyteArray array, jlong enclaveid) {
	jbyteArray result;

	jsize jArraySize = (*env)->GetArrayLength(env, array);

	// get a reference "buf" to the java byte array "array"
	jbyte * buf = (*env)->GetByteArrayElements(env, array, 0);
	size_t buffersize = jArraySize * 2 < 256 ? 256 : jArraySize * 2; // double the size, min 64 bytes.
	char * buffer = (char*)malloc(buffersize);
#ifdef CAPTURE
	memset(buffer,0,buffersize);
#endif
	memcpy(buffer, buf, jArraySize);
//	free(buf);

	int returnValue;
	size_t psize = jArraySize;
retryEnter2: ;

#ifdef CAPTURE
	printf("Enclave response: len %d\n", (int)psize);
	hexdump_clean("buffer", buffer, buffersize);
#endif

	sgx_status_t ret = ecall_handle_input_from_zookeeper(enclaveid, &psize, buffer, psize, buffersize, (int) enclaveid);
	if (ret != SGX_SUCCESS) {
		if(ret == SGX_ERROR_OUT_OF_TCS) {
			printf("out ouf tcs\n");
			sleep(1);
			goto retryEnter2;
		}
		printf("Error: Something wrong with handle input from zookeeper ecall (%X), eid=%ld.\n", (int) ret, enclaveid);
		printSgxStatus(ret);
		abort();
	}

	// we need a new array because output might be larger than input
	result = (*env)->NewByteArray(env, psize);
	(*env)->SetByteArrayRegion(env, result, 0, psize, buffer);

	// write back the changes made to "buffer" into the java "array"
	(*env)->ReleaseByteArrayElements(env, array, buf, 0);

	free(buffer);

	return result;
}
