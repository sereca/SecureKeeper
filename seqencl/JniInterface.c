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

#include "org_apache_zookeeper_server_SeqEnclave.h"
#include "utils.h"
#include "Enclave_u.h"
#include "App.h"
#include "debugflag.h"

int printSgxStatus(sgx_status_t status) {
	switch (status) {
	case SGX_SUCCESS:
//		printf("sgx status code: SGX_SUCCESS.\n");
		break;
	case SGX_ERROR_INVALID_PARAMETER:
		printf("sgx status code: SGX_ERROR_INVALID_PARAMETER.\n");
		break;
	case SGX_ERROR_OUT_OF_MEMORY:
		printf("sgx status code: SGX_ERROR_OUT_OF_MEMORY.\n");
		break;
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

int seq_eid = 0;

JNIEXPORT jint JNICALL Java_org_apache_zookeeper_server_SeqEnclave_initEnclave(JNIEnv *env, jobject obj) {
	seq_eid = enclave_init_seq();
	if (seq_eid < 0) {
		printf("error during enclave init, eid=%d.\n", seq_eid);
	}
	return (jint) seq_eid;
}

JNIEXPORT jbyteArray JNICALL Java_org_apache_zookeeper_server_SeqEnclave_getSequentialPath(JNIEnv * env, jobject obj,
		jbyteArray path, jint length) {

	jbyte* p = (*env)->GetByteArrayElements(env, path, 0);
	jsize jByteArraySize = (*env)->GetArrayLength(env, path);

	if(seq_eid <= 0) {
		printf("SeqEnclave ID <= 0. %d.\n", seq_eid);
	} else {
		int ret;
#ifdef DEBUG
		printf("path before sequential enclave: %s.\n", (char*)path);
#endif
		sgx_status_t status = ecall_get_sequential_path(seq_eid, &ret, (char*)p, (size_t)length, jByteArraySize, seq_eid);
#ifdef DEBUG
		printf("path after sequential enclave: %s.\n", (char*)path);
#endif
		printSgxStatus(status);
	}

	(*env)->ReleaseByteArrayElements(env, path, p, 0);

	return path;
}
