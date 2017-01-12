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
#include <string.h>
#include <stdlib.h>
#include <sgx_thread.h>

#include "crypto.h"
#include "list.h"
#include "Enclave.h"
//#include "debugflag.h"

static sgx_thread_mutex_t list_mutex = SGX_THREAD_MUTEX_INITIALIZER;

void insertFront(list_t * list, int32_t key, int32_t value, char * pathHash) {
	sgx_thread_mutex_lock(&list_mutex);
	// malloc element
	element_t* new_element = (element_t*) malloc(sizeof(element_t));

	// set values
	new_element->key = key;
	new_element->value = value;
	new_element->previous = NULL;

	if(pathHash != NULL) {
		memcpy(new_element->pathhash, pathHash, HASHLEN);
	}

	// make second element point back to new element
	if (list->head != NULL) {
		list->head->previous = new_element;
	} else {
		// list is new, first element
		list->tail = new_element;
	}

	// change head pointer
	list->head = new_element;
	sgx_thread_mutex_unlock(&list_mutex);
}

int32_t removeEnd(list_t * list, int32_t key, char * pathHash) {
	sgx_thread_mutex_lock(&list_mutex);
	// get list tail element
	element_t* element = list->tail;

	// just double check key should equal given key
	if (key != element->key) {
		printf("ERROR: list->removeEnd() found value with wrong key. Should never possibly happen.\n");
	}

	// get value
	int32_t val = element->value;

	// change tail pointer
	list->tail = element->previous;

	if (element->previous == NULL) {
		// last element removed
		list->head = NULL;
	}

	if(pathHash != NULL) {
		memcpy(pathHash, element->pathhash, HASHLEN);
	}

	// delete element
	free(element);

	sgx_thread_mutex_unlock(&list_mutex);
	return val;
}
