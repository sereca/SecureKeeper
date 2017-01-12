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
#ifndef _LIST_H_
#define _LIST_H_

#include <stdint.h>

// This structure represents one list entry
typedef struct element {
	int key;
	int32_t value;
	struct element *previous;
	int8_t pathhash[32];
} element_t;

// This structure represents one list
typedef struct list {
	element_t *head;
	element_t *tail;
} list_t;

void insertFront(list_t * list, int32_t key, int32_t value, char * pathHash);
int32_t removeEnd(list_t * list, int32_t key, char * pathHash);

#endif
