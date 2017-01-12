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
 * This header file contains functions which provide the ability to change and
 * analyze the input stored in a given buffer.
 * */
#include "list.h"
#include "utils.h"
#ifndef _ZOOKEEPER_H_
#define _ZOOKEEPER_H_

typedef enum {
	ZOOKEEPER = 0, CLIENT = 1,
} sender_t;

/**
 * The following functions handle the input of length
 * p_package->size coming from a connected zookeeper or client.
 * p_package->size  is set to the new size, p_package->buffer is freed, 
 * afterwards p_package->buffer contains output.
 * If the input should be return to the source,
 *  2 is returned, 1, if changed were made, 0 otherwise
 **/

size_t ecall_handle_input_from_client(char * buffer, size_t psize, size_t buffersize, int eid);
size_t ecall_handle_input_from_zookeeper(char * buffer, size_t psize, size_t buffersize, int eid);
#endif
